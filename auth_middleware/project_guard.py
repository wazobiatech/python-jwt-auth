# auth_middleware/project_guard.py
"""
Redis-cached JWKS Authentication Middleware for Platform, Project & Service Tokens.
Mirrors the Node.js ProjectAuthMiddleware (project.guard.ts).
"""
import os
import json
import time
import hmac
import hashlib
import base64
import logging
from typing import Optional, Dict, Any, List, Tuple

import jwt
import requests
from jose import jwk as jose_jwk

from .types import (
    AuthenticatedRequest,
    PlatformTokenPayload,
    ProjectTokenPayload,
    ServiceTokenPayload,
    PlatformContext,
    ProjectContext,
    ServiceContext,
)
from .utils.redis_connection import get_redis
from .services.auth import generate_token, get_service_by_id

logger = logging.getLogger(__name__)


class ProjectAuthMiddleware:
    """JWT-based authentication middleware for platform, project and service tokens."""

    def __init__(self, service_name: str):
        self.service_name = service_name.lower()
        self.mercury_base_url = os.getenv('MERCURY_BASE_URL', 'http://localhost:4000')
        self.signature_secret = os.getenv('SIGNATURE_SHARED_SECRET', '')
        self.service_jwks_cache_key = 'service_jwks_cache'
        self.jwks_cache_ttl = int(os.getenv('JWKS_CACHE_TTL', '18000'))  # 5 hours

    # ─────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────

    async def authenticate(self, req: AuthenticatedRequest) -> None:
        """
        Main authentication entry-point.
        Extracts token from ``x-project-token`` header, validates it via JWKS,
        then routes by token type (platform / project / service).
        """
        try:
            auth_header = req.headers.get('x-project-token')

            if not auth_header:
                raise Exception("No token provided, required_header: 'x-project-token'")

            token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header
            if not token:
                raise Exception('Empty token')

            validation = await self._validate_token(token)

            if not validation['is_valid']:
                raise Exception(f"Invalid token: {validation['error']}")

            payload = validation['payload']

            # Route based on token type
            if payload['type'] == 'platform':
                self._inject_platform_context(req, PlatformTokenPayload.from_dict(payload))
            elif payload['type'] == 'project':
                await self._inject_project_context(req, ProjectTokenPayload.from_dict(payload))
            elif payload['type'] == 'service':
                self._inject_service_context(req, ServiceTokenPayload.from_dict(payload))
            else:
                raise Exception(f"Invalid token type: {payload.get('type')}")

        except Exception as e:
            raise Exception(f"Authentication service error: {str(e)}")

    # ─────────────────────────────────────────
    # Context injection
    # ─────────────────────────────────────────

    def _inject_platform_context(
        self, req: AuthenticatedRequest, payload: PlatformTokenPayload
    ) -> None:
        req.platform = PlatformContext(
            tenant_id=payload.tenant_id,
            project_uuid=payload.tenant_id,
            scopes=payload.scopes or [],
            token_id=payload.token_id,
            expires_at=payload.exp,
        )

    async def _inject_project_context(
        self, req: AuthenticatedRequest, payload: ProjectTokenPayload
    ) -> None:
        enabled_services = payload.enabled_services or []

        logger.info('Injecting project context', extra={
            'tenant_id': payload.tenant_id,
            'token_id': payload.token_id,
            'enabled_services': enabled_services,
        })

        # Generate a service token via Mercury (client credentials)
        access_token = await generate_token()
        logger.info('Access token generated', extra={
            'access_token_preview': access_token[:20],
        })

        # Resolve our own service UUID
        service_id = await get_service_by_id(access_token)
        logger.info('Service uuid found', extra={'service_id': service_id})

        if service_id not in enabled_services:
            logger.error('Service access denied', extra={
                'tenant_id': payload.tenant_id,
                'service_id': service_id,
                'enabled_services': enabled_services,
            })
            raise Exception(
                f"Service access denied. Service '{service_id}' is not enabled for this project. "
                f"Enabled services: {', '.join(enabled_services)}"
            )

        logger.info('Service is enabled for this project', extra={
            'enabled_services': enabled_services, 'service_id': service_id,
        })

        req.project = ProjectContext(
            tenant_id=payload.tenant_id,
            project_uuid=payload.tenant_id,
            enabled_services=enabled_services,
            scopes=payload.scopes or [],
            secret_version=payload.secret_version,
            token_id=payload.token_id,
            expires_at=payload.exp,
        )

        logger.info('Project context injected successfully', extra={
            'tenant_id': payload.tenant_id,
            'token_id': payload.token_id,
            'service_id': service_id,
            'scopes': req.project.scopes,
        })

    def _inject_service_context(
        self, req: AuthenticatedRequest, payload: ServiceTokenPayload
    ) -> None:
        scopes = payload.scope.split(' ') if payload.scope else []

        req.service = ServiceContext(
            client_id=payload.client_id,
            service_name=payload.service_name,
            scopes=scopes,
            token_id=payload.jti,
            issued_at=payload.iat,
            expires_at=payload.exp,
        )
        logger.info(
            f"Service authenticated: {payload.service_name}, scopes: {', '.join(scopes)}"
        )

    # ─────────────────────────────────────────
    # Token validation
    # ─────────────────────────────────────────

    async def _validate_token(self, token: str) -> Dict[str, Any]:
        """Validate token using cached JWKS + RSA verification, then dispatch to type-specific validation."""
        try:
            public_key = await self._get_public_key_from_cache(token)

            try:
                verified = jwt.decode(
                    token,
                    public_key,
                    algorithms=['RS512'],
                    options={
                        'verify_exp': True,
                        'verify_aud': False,
                        'verify_iss': False,
                    },
                )
            except jwt.ExpiredSignatureError:
                return {'is_valid': False, 'error': 'Token has expired'}
            except jwt.InvalidTokenError as e:
                return {'is_valid': False, 'error': f"Invalid token: {str(e)}"}

            token_type = verified.get('type')

            if token_type == 'platform':
                return await self._validate_platform_token(verified)
            elif token_type == 'project':
                return await self._validate_project_token(verified)
            elif token_type == 'service':
                return self._validate_service_token(verified)
            else:
                return {'is_valid': False, 'error': f"Unsupported token type: {token_type}"}

        except Exception as e:
            return {'is_valid': False, 'error': str(e)}

    async def _validate_platform_token(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not payload.get('tenant_id') or not payload.get('token_id'):
            return {'is_valid': False, 'error': 'Invalid platform token structure'}

        redis = await get_redis()
        token_key = f"platform_token:{payload['token_id']}"
        try:
            exists = redis.client.exists(token_key)
        except Exception:
            exists = 1  # Allow if Redis unavailable

        if not exists:
            return {'is_valid': False, 'error': 'Token has been revoked'}

        return {'is_valid': True, 'payload': payload}

    async def _validate_project_token(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if (
            not payload.get('tenant_id')
            or not payload.get('token_id')
            or not isinstance(payload.get('enabled_services'), list)
        ):
            return {'is_valid': False, 'error': 'Invalid project token structure'}

        # Check secret version
        current_version = await self._get_current_secret_version(payload['tenant_id'])
        if current_version > 0 and payload.get('secret_version', 0) < current_version:
            return {
                'is_valid': False,
                'error': (
                    f"Token secret version outdated "
                    f"(token: {payload.get('secret_version')}, current: {current_version}) "
                    f"- re-authentication required"
                ),
            }

        # Check revocation
        redis = await get_redis()
        token_key = f"project_token:{payload['token_id']}"
        try:
            exists = redis.client.exists(token_key)
        except Exception:
            exists = 1

        if not exists:
            return {'is_valid': False, 'error': 'Token has been revoked'}

        return {'is_valid': True, 'payload': payload}

    def _validate_service_token(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Service tokens are stateless — only signature + expiration validation."""
        if not payload.get('client_id') or not payload.get('service_name') or not payload.get('jti'):
            return {'is_valid': False, 'error': 'Invalid service token structure'}

        return {'is_valid': True, 'payload': payload}

    # ─────────────────────────────────────────
    # JWKS helpers
    # ─────────────────────────────────────────

    async def _get_public_key_from_cache(self, token: str) -> str:
        """
        Get RSA public key from Redis-cached JWKS.
        Determines the correct JWKS endpoint based on token type
        (service → auth/service/..., others → auth/projects/{tenant_id}/...).
        Auto-refreshes on key miss.
        """
        try:
            header = self._decode_jwt_header(token)
            kid = header.get('kid')
            if not kid:
                raise Exception('Missing key ID in token header')

            payload = self._decode_jwt_payload(token)

            # Determine JWKS endpoint and cache key based on token type
            if payload.get('type') == 'service':
                cache_key = self.service_jwks_cache_key
                jwks_path = 'auth/service/.well-known/jwks.json'
                logger.info('Service token detected, using service JWKS endpoint')
            else:
                tenant_id = payload.get('tenant_id', '')
                cache_key = f"jwks_cache:{tenant_id}"
                jwks_path = f"auth/projects/{tenant_id}/.well-known/jwks.json"
                logger.info(f"{payload.get('type')} token detected, tenant_id: {tenant_id}")

            # Check Redis for cached JWKS
            redis = await get_redis()
            cached_jwks = await redis.get(cache_key)

            if cached_jwks:
                logger.info('Using cached JWKS from Redis')
                jwks_data = cached_jwks if isinstance(cached_jwks, dict) else json.loads(cached_jwks)

                # Try to find the key
                pem = self._find_key_in_jwks(jwks_data, kid)
                if pem:
                    return pem

                # Auto-refresh: key not found in cache
                logger.info(f"Key {kid} not found in cache, fetching fresh JWKS")
                jwks_data = await self._fetch_and_cache_jwks(jwks_path, cache_key)
                pem = self._find_key_in_jwks(jwks_data, kid)
                if not pem:
                    raise Exception(f"Key {kid} not found even after JWKS refresh")
                return pem
            else:
                logger.info('No cached JWKS found, fetching from Mercury')
                jwks_data = await self._fetch_and_cache_jwks(jwks_path, cache_key)
                pem = self._find_key_in_jwks(jwks_data, kid)
                if not pem:
                    raise Exception(f"Key {kid} not found in JWKS")
                return pem

        except Exception as e:
            raise Exception(f"Failed to get public key: {str(e)}")

    async def _fetch_and_cache_jwks(self, path: str, cache_key: str) -> Dict[str, Any]:
        """Fetch JWKS from Mercury with HMAC-signed request and cache in Redis."""
        jwks_uri = f"{self.mercury_base_url}/{path}"
        timestamp = str(int(time.time() * 1000))
        signature_input = f"GET/{path}{timestamp}"

        signature = hmac.new(
            self.signature_secret.encode(),
            signature_input.encode(),
            hashlib.sha256,
        ).hexdigest()

        headers = {
            'Accept': 'application/json',
            'User-Agent': 'Mercury-Auth-SDK/2.0',
            'X-Timestamp': timestamp,
            'X-Signature': signature,
        }

        try:
            response = requests.get(jwks_uri, headers=headers, timeout=10)

            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")

            jwks_data = response.json()

            if not jwks_data or 'keys' not in jwks_data:
                raise Exception('Invalid JWKS response')

            # Cache in Redis
            redis = await get_redis()
            await redis.set(cache_key, jwks_data, {'EX': self.jwks_cache_ttl})
            logger.info(f"JWKS cached successfully with key: {cache_key}")

            return jwks_data

        except requests.exceptions.ConnectionError:
            raise Exception('Mercury service unavailable')
        except requests.exceptions.Timeout:
            raise Exception('Mercury service timeout')
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to fetch JWKS: {str(e)}")

    # ─────────────────────────────────────────
    # Utility methods
    # ─────────────────────────────────────────

    @staticmethod
    def _find_key_in_jwks(jwks_data: Dict[str, Any], kid: str) -> Optional[str]:
        """Find a key by kid in JWKS data and return PEM string, or None."""
        for key in jwks_data.get('keys', []):
            if key.get('kid') == kid:
                return jose_jwk.construct(key).to_pem().decode('utf-8')
        return None

    @staticmethod
    def _decode_jwt_header(token: str) -> Dict[str, Any]:
        parts = token.split('.')
        if len(parts) != 3:
            raise Exception('Invalid JWT format')
        header_b64 = parts[0]
        padding = len(header_b64) % 4
        if padding:
            header_b64 += '=' * (4 - padding)
        return json.loads(base64.urlsafe_b64decode(header_b64).decode())

    @staticmethod
    def _decode_jwt_payload(token: str) -> Dict[str, Any]:
        parts = token.split('.')
        if len(parts) != 3:
            raise Exception('Invalid JWT format')
        payload_b64 = parts[1]
        padding = len(payload_b64) % 4
        if padding:
            payload_b64 += '=' * (4 - padding)
        return json.loads(base64.urlsafe_b64decode(payload_b64).decode())

    async def _get_current_secret_version(self, tenant_id: str) -> int:
        """Get current secret version from Redis (cached by Mercury)."""
        try:
            redis = await get_redis()
            cache_key = f"tenant_secret_version:{tenant_id}"
            cached_version = await redis.get(cache_key)

            if cached_version is not None:
                return int(cached_version)

            return 0  # Default to allow if not found
        except Exception as e:
            raise Exception(f"Failed to get secret version: {str(e)}")

    def set_cache_ttl(self, seconds: int) -> None:
        """Update JWKS cache TTL."""
        self.jwks_cache_ttl = seconds
