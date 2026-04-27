# auth_middleware/jwt_guard.py
import os
import json
import base64
import hmac
import hashlib
import time
import logging
from typing import Dict, Optional, Any, Tuple
import jwt
import requests
from jose import jwk
from .types import AuthenticatedRequest, AuthUser
from .utils.redis_connection import get_redis

logger = logging.getLogger(__name__)


class JwtAuthMiddleware:
    """Advanced JWT Authentication with JWKS support"""
    
    def __init__(self):
        domain = os.getenv('MERCURY_BASE_URL', 'http://localhost:4000')
        self.expected_issuer = domain
        self.jwks_cache: Dict[str, Dict[str, Any]] = {}
        self.signature_secret = os.getenv('SIGNATURE_SHARED_SECRET', '')
        self.cache_expiry_time = int(os.getenv('CACHE_EXPIRY_TIME', '3600'))
    
    async def authenticate(self, req: AuthenticatedRequest) -> None:
        """
        Authenticate request using JWT token
        
        Args:
            req: AuthenticatedRequest object
            
        Raises:
            Exception: If authentication fails
        """
        auth_header = req.headers.get('authorization')
        
        if not auth_header:
            raise Exception('No authorization header provided')
        
        token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header
        
        if not token:
            raise Exception('No token provided')
        
        try:
            # Get signing key from JWKS
            public_key = await self._get_signing_key(token)
            
            # Validate token
            user = await self._validate(token, public_key)
            
            logger.info('[JWT-DEBUG] Token validation successful', extra={
                'uuid': user.get('uuid'),
                'email': user.get('email'),
                'permissions_length': len(user.get('permissions', [])),
            })
            
            req.user = {
                **user,
                'tenant_id': user.get('tenant_id', ''),
                'permissions': user.get('permissions', []),
                'token_id': user.get('token_id', ''),
            }
            
        except Exception as e:
            logger.error(f"JWT verification failed: {str(e)}")
            raise Exception(f"Invalid JWT token: {str(e)}")
    
    def _decode_jwt_token_for_tenant_id(self, raw_jwt_token: str) -> Optional[str]:
        """
        Decode JWT token to extract tenant_id
        
        Args:
            raw_jwt_token: Raw JWT token string
            
        Returns:
            Tenant ID if present, None otherwise
        """
        try:
            parts = raw_jwt_token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode without verification to get tenant_id
            decoded = jwt.decode(raw_jwt_token, options={"verify_signature": False})
            
            if decoded and isinstance(decoded, dict):
                return decoded.get('tenant_id')
            
            return None
        except Exception:
            return None
    
    def _get_jwks_uri_and_path(self, tenant_id: Optional[str]) -> Tuple[str, str]:
        """
        Get JWKS URI and path for tenant
        
        Args:
            tenant_id: Tenant ID
            
        Returns:
            Tuple of (URI, path)
            
        Raises:
            Exception: If no tenant_id available
        """
        domain = os.getenv('MERCURY_BASE_URL', 'http://localhost:4000')
        
        if not tenant_id:
            raise Exception(
                'No tenant_id found in token'
            )
        
        path = f"auth/projects/{tenant_id}/.well-known/jwks.json"
        uri = f"{domain}/{path}"
        return uri, path
    
    async def _fetch_jwks(self, jwks_uri: str, path: str) -> Dict[str, Any]:
        """
        Fetch JWKS from endpoint
        
        Args:
            jwks_uri: JWKS endpoint URI
            path: Request path for signature
            
        Returns:
            JWKS key store
            
        Raises:
            Exception: If fetch fails
        """
        try:
            timestamp = str(int(time.time() * 1000))
            signature_input = f"GET/{path}{timestamp}"
            
            signature = hmac.new(
                self.signature_secret.encode(),
                signature_input.encode(),
                hashlib.sha256
            ).hexdigest()
            
            headers = {
                'Accept': 'application/json',
                'User-Agent': 'Python-JWT-Strategy/1.0',
                'X-Timestamp': timestamp,
                'X-Signature': signature,
            }
            
            response = requests.get(jwks_uri, headers=headers, timeout=10)
            
            if response.status_code != 200:
                raise Exception(
                    f"JWKS endpoint returned {response.status_code}: {response.text}"
                )
            
            data = response.json()
            
            if not data or 'keys' not in data:
                raise Exception('Invalid JWKS response: missing keys')
            
            return data
            
        except requests.exceptions.ConnectionError:
            raise Exception('JWKS endpoint not reachable')
        except requests.exceptions.Timeout:
            raise Exception('JWKS endpoint timeout')
        except Exception as e:
            raise Exception(f"Failed to fetch JWKS: {str(e)}")
    
    async def _get_signing_key(self, raw_jwt_token: str) -> str:
        """
        Get signing key for JWT token
        
        Args:
            raw_jwt_token: Raw JWT token
            
        Returns:
            Public key in PEM format
            
        Raises:
            Exception: If key cannot be obtained
        """
        try:
            parts = raw_jwt_token.split('.')
            if len(parts) != 3:
                raise Exception(f"Invalid JWT format: expected 3 parts, got {len(parts)}")
            
            # Decode header
            header_base64 = parts[0]
            # Add padding if needed
            header_base64 += '=' * (4 - len(header_base64) % 4)
            header_json = base64.urlsafe_b64decode(header_base64).decode('utf-8')
            header = json.loads(header_json)
            
            if 'kid' not in header:
                raise Exception('Missing key ID (kid) in token header')
            
            kid = header['kid']
            tenant_id = self._decode_jwt_token_for_tenant_id(raw_jwt_token)
            jwks_uri, path = self._get_jwks_uri_and_path(tenant_id)
            
            cache_key = tenant_id or 'default'
            
            # Check cache
            if cache_key in self.jwks_cache:
                cached_entry = self.jwks_cache[cache_key]
                if time.time() < cached_entry['expiry']:
                    jwks_data = cached_entry['keystore']
                else:
                    # Cache expired, fetch new
                    jwks_data = await self._fetch_jwks(jwks_uri, path)
                    self.jwks_cache[cache_key] = {
                        'keystore': jwks_data,
                        'expiry': time.time() + 600  # 10 minutes
                    }
            else:
                # Not in cache, fetch
                jwks_data = await self._fetch_jwks(jwks_uri, path)
                self.jwks_cache[cache_key] = {
                    'keystore': jwks_data,
                    'expiry': time.time() + 600  # 10 minutes
                }
            
            # Find the key
            key_data = None
            for key in jwks_data['keys']:
                if key.get('kid') == kid:
                    key_data = key
                    break
            
            if not key_data:
                raise Exception(
                    f"Key {kid} not found in JWKS for tenant {tenant_id or 'default'}"
                )
            
            # Convert JWK to PEM
            public_key = jwk.construct(key_data).to_pem().decode('utf-8')
            return public_key
            
        except Exception as e:
            raise Exception(f"Unable to get signing key: {str(e)}")
    
    def _create_token_cache_key(self, raw_token: str) -> str:
        """Create token cache key - matches Node.js SHA256 implementation"""
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()[:32]
        return f"validated_token:{token_hash}"
    
    async def _cache_validated_token(self, payload: Dict[str, Any], raw_token: str) -> None:
        """Cache validated token"""
        try:
            redis = await get_redis()
            
            cache_key = self._create_token_cache_key(raw_token)
            
            await redis.set(cache_key, payload, {'EX': self.cache_expiry_time})
        except Exception as e:
            logger.warning(f"Failed to cache token: {e}")
    
    async def _get_cached_token(self, raw_token: str) -> Optional[Dict[str, Any]]:
        """Get cached token"""
        try:
            redis = await get_redis()
            
            cache_key = self._create_token_cache_key(raw_token)
            
            cached_payload = await redis.get(cache_key)
            
            if cached_payload:
                # Check expiration
                now = int(time.time())
                if cached_payload.get('exp', 0) < now:
                    await redis.delete(cache_key)
                    return None
                return cached_payload
            
            return None
        except Exception:
            return None
    
    async def _validate(self, raw_token: str, public_key: str) -> AuthUser:
        """
        Validate JWT token
        
        Args:
            raw_token: Raw JWT token
            public_key: Public key in PEM format
            
        Returns:
            Authenticated user information
            
        Raises:
            Exception: If validation fails
        """
        # Check cache first
        cached_payload = await self._get_cached_token(raw_token)
        if cached_payload:
            sub = cached_payload.get('sub', {})
            return AuthUser(
                uuid=sub.get('uuid'),
                email=sub.get('email'),
                name=sub.get('name'),
                tenant_id=cached_payload.get('project_uuid') or cached_payload.get('tenant_id', ''),
                permissions=cached_payload.get('permissions', []),
                token_id=cached_payload.get('jti', ''),
            )
        
        try:
            # Verify the token using the public key
            verified = jwt.decode(
                raw_token,
                public_key,
                algorithms=['RS512'],
                options={'verify_exp': True, "verify_aud": False},
                audience=None
            )
            
            if not verified or not isinstance(verified, dict):
                raise Exception('Invalid JWT payload')
            
            # Validate the payload structure
            if 'sub' not in verified or not verified['sub'].get('uuid'):
                raise Exception('Invalid JWT payload structure')
            
            # Validate issuer
            if verified.get('iss') != self.expected_issuer:
                raise Exception(
                    f"Invalid issuer. Expected: {self.expected_issuer}, Got: {verified.get('iss')}"
                )
            
            # Validate timestamps
            now = int(time.time())
            
            if verified.get('exp', 0) < now:
                raise Exception('Token expired')
            
            if verified.get('nbf', now + 1) > now:
                raise Exception('Token not yet valid')
            
            # Check Redis for token revocation
            if verified.get('jti'):
                try:
                    redis = await get_redis()
                    is_revoked = await redis.get(f"revoked_token:{verified['jti']}")
                    
                    if is_revoked:
                        raise Exception('Token has been revoked')
                except Exception as e:
                    # Continue authentication even if Redis is unavailable
                    logger.warning(f"Redis revocation check failed, continuing: {str(e)}")
            
            # Cache the validated token
            await self._cache_validated_token(verified, raw_token)
            
            sub = verified['sub']
            return AuthUser(
                uuid=sub['uuid'],
                email=sub['email'],
                name=sub['name'],
                tenant_id=verified.get('project_uuid') or verified.get('tenant_id', ''),
                permissions=verified.get('permissions', []),
                token_id=verified.get('jti', ''),
            )
            
        except jwt.ExpiredSignatureError:
            raise Exception('Token expired')
        except jwt.InvalidTokenError as e:
            raise Exception(f"Token validation failed: {str(e)}")
        except Exception as e:
            raise Exception(f"Token validation failed: {str(e)}")