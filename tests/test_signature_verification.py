"""
End-to-end signature-verification tests using real RSA keypairs.

These tests intentionally do NOT mock ``jwt.decode`` so they fail loudly if
``verify_signature=False`` ever creeps into the validation path.

For each token type we:
  1. Generate two RSA keypairs (the "trusted" Mercury key and a "wrong" key).
  2. Sign a token with the trusted key.
  3. Stub the JWKS endpoint to return ONLY the trusted public key.
  4. Verify a happy-path validation succeeds.
  5. Sign the same token shape with the WRONG key.
  6. Verify the middleware rejects it.
"""
import time
import json
import base64
import pytest
import jwt
from unittest.mock import AsyncMock, MagicMock, patch

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from auth_middleware.project_guard import ProjectAuthMiddleware, AuthenticationError
from auth_middleware.types import AuthenticatedRequest


# ─────────────────────────────────────────────
# Keypair / JWKS helpers
# ─────────────────────────────────────────────

def _make_rsa_keypair():
    """Return (private_pem, public_pem, jwks_dict_for_kid_K1)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    numbers = key.public_key().public_numbers()
    n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')
    e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')
    jwk = {
        'kty': 'RSA',
        'kid': 'K1',
        'use': 'sig',
        'alg': 'RS512',
        'n': base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode(),
        'e': base64.urlsafe_b64encode(e_bytes).rstrip(b'=').decode(),
    }
    return private_pem, public_pem, {'keys': [jwk]}


def _sign(payload: dict, private_pem: str) -> str:
    return jwt.encode(payload, private_pem, algorithm='RS512', headers={'kid': 'K1'})


def _now() -> int:
    return int(time.time())


@pytest.fixture(scope='module')
def trusted_keypair():
    return _make_rsa_keypair()


@pytest.fixture(scope='module')
def wrong_keypair():
    return _make_rsa_keypair()


@pytest.fixture
def middleware():
    return ProjectAuthMiddleware('test-service')


@pytest.fixture
def mock_request():
    request = MagicMock()
    request.headers = {}
    return AuthenticatedRequest(request)


def _patch_jwks(jwks_dict):
    """Patch the JWKS fetch + Redis layer to return ``jwks_dict``."""
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)  # force fresh fetch
    mock_redis.set = AsyncMock(return_value=True)
    mock_redis.exists = AsyncMock(return_value=True)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = jwks_dict

    return (
        patch('auth_middleware.project_guard.requests.get', return_value=mock_response),
        patch('auth_middleware.project_guard.get_redis', new_callable=AsyncMock, return_value=mock_redis),
    )


# ─────────────────────────────────────────────
# Platform token
# ─────────────────────────────────────────────

class TestPlatformTokenSignature:

    @pytest.mark.asyncio
    async def test_correct_key_succeeds(self, middleware, mock_request, trusted_keypair):
        priv, _pub, jwks = trusted_keypair
        payload = {
            'type': 'platform',
            'tenant_id': 'tenant-A',
            'token_id': 'tok-1',
            'secret_version': 1,
            'scopes': ['admin:read'],
            'iat': _now(), 'nbf': _now() - 10, 'exp': _now() + 600,
            'iss': 'http://m', 'aud': 'http://m',
        }
        token = _sign(payload, priv)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        get_patch, redis_patch = _patch_jwks(jwks)
        with get_patch, redis_patch:
            await middleware.authenticate(mock_request)

        assert mock_request.platform is not None
        assert mock_request.platform.tenant_id == 'tenant-A'

    @pytest.mark.asyncio
    async def test_wrong_key_rejected(self, middleware, mock_request, trusted_keypair, wrong_keypair):
        """A token signed by the wrong key MUST fail verification."""
        _trusted_priv, _trusted_pub, trusted_jwks = trusted_keypair
        wrong_priv, _, _ = wrong_keypair

        payload = {
            'type': 'platform',
            'tenant_id': 'tenant-A',
            'token_id': 'tok-1',
            'secret_version': 1,
            'scopes': ['admin:read'],
            'iat': _now(), 'nbf': _now() - 10, 'exp': _now() + 600,
            'iss': 'http://m', 'aud': 'http://m',
        }
        # Signed with WRONG key — JWKS only contains the trusted public key.
        token = _sign(payload, wrong_priv)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        get_patch, redis_patch = _patch_jwks(trusted_jwks)
        with get_patch, redis_patch:
            with pytest.raises(AuthenticationError):
                await middleware.authenticate(mock_request)


# ─────────────────────────────────────────────
# Project token
# ─────────────────────────────────────────────

class TestProjectTokenSignature:

    @pytest.mark.asyncio
    async def test_correct_key_succeeds(self, middleware, mock_request, trusted_keypair):
        priv, _, jwks = trusted_keypair
        payload = {
            'type': 'project',
            'tenant_id': 'tenant-A',
            'token_id': 'tok-2',
            'secret_version': 1,
            'enabled_services': ['svc-uuid-1'],
            'scopes': ['posts:read'],
            'iat': _now(), 'nbf': _now() - 10, 'exp': _now() + 600,
            'iss': 'http://m', 'aud': 'http://m',
        }
        token = _sign(payload, priv)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        get_patch, redis_patch = _patch_jwks(jwks)
        with get_patch, redis_patch, \
             patch('auth_middleware.project_guard.generate_token', new_callable=AsyncMock, return_value='svc-tok'), \
             patch('auth_middleware.project_guard.get_service_by_id', new_callable=AsyncMock, return_value='svc-uuid-1'):
            await middleware.authenticate(mock_request)

        assert mock_request.project is not None
        assert mock_request.project.tenant_id == 'tenant-A'
        assert mock_request.project.enabled_services == ['svc-uuid-1']

    @pytest.mark.asyncio
    async def test_wrong_key_rejected(self, middleware, mock_request, trusted_keypair, wrong_keypair):
        _trusted_priv, _, trusted_jwks = trusted_keypair
        wrong_priv, _, _ = wrong_keypair

        payload = {
            'type': 'project',
            'tenant_id': 'tenant-A',
            'token_id': 'tok-2',
            'secret_version': 1,
            'enabled_services': ['svc-uuid-1'],
            'scopes': ['posts:read'],
            'iat': _now(), 'nbf': _now() - 10, 'exp': _now() + 600,
            'iss': 'http://m', 'aud': 'http://m',
        }
        token = _sign(payload, wrong_priv)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        get_patch, redis_patch = _patch_jwks(trusted_jwks)
        with get_patch, redis_patch:
            with pytest.raises(AuthenticationError):
                await middleware.authenticate(mock_request)


# ─────────────────────────────────────────────
# Service token
# ─────────────────────────────────────────────

class TestServiceTokenSignature:

    @pytest.mark.asyncio
    async def test_correct_key_succeeds(self, middleware, mock_request, trusted_keypair):
        priv, _, jwks = trusted_keypair
        payload = {
            'type': 'service',
            'client_id': 'client-001',
            'service_name': 'analytics',
            'scope': 'services:read',
            'jti': 'jti-1',
            'iat': _now(), 'nbf': _now() - 10, 'exp': _now() + 600,
            'iss': 'http://m', 'aud': 'http://m',
        }
        token = _sign(payload, priv)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        get_patch, redis_patch = _patch_jwks(jwks)
        with get_patch, redis_patch:
            await middleware.authenticate(mock_request)

        assert mock_request.service is not None
        assert mock_request.service.client_id == 'client-001'

    @pytest.mark.asyncio
    async def test_wrong_key_rejected(self, middleware, mock_request, trusted_keypair, wrong_keypair):
        _trusted_priv, _, trusted_jwks = trusted_keypair
        wrong_priv, _, _ = wrong_keypair

        payload = {
            'type': 'service',
            'client_id': 'client-001',
            'service_name': 'analytics',
            'scope': 'services:read',
            'jti': 'jti-1',
            'iat': _now(), 'nbf': _now() - 10, 'exp': _now() + 600,
            'iss': 'http://m', 'aud': 'http://m',
        }
        token = _sign(payload, wrong_priv)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        get_patch, redis_patch = _patch_jwks(trusted_jwks)
        with get_patch, redis_patch:
            with pytest.raises(AuthenticationError):
                await middleware.authenticate(mock_request)
