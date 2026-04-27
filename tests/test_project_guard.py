import pytest
import json
import time
import base64
import jwt
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from auth_middleware.project_guard import ProjectAuthMiddleware
from auth_middleware.types import AuthenticatedRequest


# ── Helpers ──────────────────────────────────────────────────────

def _make_token(payload: dict, key: str = 'secret', algorithm: str = 'HS256') -> str:
    return jwt.encode(payload, key, algorithm=algorithm)


def _base_platform_payload(**overrides) -> dict:
    now = int(time.time())
    base = {
        'type': 'platform',
        'tenant_id': 'tenant-abc',
        'token_id': 'tok-plat-1',
        'secret_version': 1,
        'scopes': ['admin:read'],
        'iat': now,
        'nbf': now - 10,
        'exp': now + 3600,
        'iss': 'http://localhost:4000',
        'aud': 'http://localhost:4000',
    }
    base.update(overrides)
    return base


def _base_project_payload(**overrides) -> dict:
    now = int(time.time())
    base = {
        'type': 'project',
        'tenant_id': 'tenant-xyz',
        'token_id': 'tok-proj-1',
        'secret_version': 1,
        'enabled_services': ['svc-uuid-1', 'svc-uuid-2'],
        'scopes': ['posts:read'],
        'iat': now,
        'nbf': now - 10,
        'exp': now + 3600,
        'iss': 'http://localhost:4000',
        'aud': 'http://localhost:4000',
    }
    base.update(overrides)
    return base


def _base_service_payload(**overrides) -> dict:
    now = int(time.time())
    base = {
        'type': 'service',
        'client_id': 'client-001',
        'service_name': 'analytics',
        'scope': 'services:read services:write',
        'jti': 'jti-svc-1',
        'iat': now,
        'nbf': now - 10,
        'exp': now + 3600,
        'iss': 'http://localhost:4000',
        'aud': 'http://localhost:4000',
    }
    base.update(overrides)
    return base


# ── Tests ────────────────────────────────────────────────────────

class TestProjectAuthMiddleware:

    @pytest.fixture
    def middleware(self):
        return ProjectAuthMiddleware(service_name='test-service')

    @pytest.fixture
    def mock_request(self):
        request = Mock()
        request.headers = {}
        return AuthenticatedRequest(request)

    # ── Missing / empty token ────────────────────────────────────

    @pytest.mark.asyncio
    async def test_missing_token_header(self, middleware, mock_request):
        """Fails when x-project-token header is absent"""
        with pytest.raises(Exception, match="No token provided"):
            await middleware.authenticate(mock_request)

    @pytest.mark.asyncio
    async def test_empty_token(self, middleware, mock_request):
        """Fails when token is empty after stripping Bearer prefix"""
        mock_request.request.headers = {'x-project-token': 'Bearer '}
        with pytest.raises(Exception, match="Empty token"):
            await middleware.authenticate(mock_request)

    # ── Invalid token type ───────────────────────────────────────

    @pytest.mark.asyncio
    async def test_unsupported_token_type(self, middleware, mock_request):
        """Fails for unknown token type"""
        payload = _base_platform_payload(type='unknown')
        token = _make_token(payload)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        with patch.object(middleware, '_get_public_key_from_cache', new_callable=AsyncMock, return_value='mock_key'):
            with patch('auth_middleware.project_guard.jwt.decode', return_value=payload):
                with pytest.raises(Exception, match="Unsupported token type"):
                    await middleware.authenticate(mock_request)

    # ── Platform token ───────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_platform_token_injects_platform_context(self, middleware, mock_request):
        """Platform token sets req.platform with correct fields"""
        payload = _base_platform_payload()
        token = _make_token(payload)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        mock_redis = AsyncMock()
        mock_redis.client = MagicMock()
        mock_redis.client.exists.return_value = 1

        with patch.object(middleware, '_get_public_key_from_cache', new_callable=AsyncMock, return_value='mock_key'):
            with patch('auth_middleware.project_guard.jwt.decode', return_value=payload):
                with patch('auth_middleware.project_guard.get_redis', new_callable=AsyncMock, return_value=mock_redis):
                    await middleware.authenticate(mock_request)

        assert mock_request.platform is not None
        assert mock_request.platform.tenant_id == 'tenant-abc'
        assert mock_request.platform.token_id == 'tok-plat-1'
        assert mock_request.platform.scopes == ['admin:read']
        assert mock_request.project is None
        assert mock_request.service is None

    @pytest.mark.asyncio
    async def test_platform_token_revoked(self, middleware, mock_request):
        """Platform token fails when revoked (not found in Redis)"""
        payload = _base_platform_payload()
        token = _make_token(payload)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        mock_redis = AsyncMock()
        mock_redis.client = MagicMock()
        mock_redis.client.exists.return_value = 0

        with patch.object(middleware, '_get_public_key_from_cache', new_callable=AsyncMock, return_value='mock_key'):
            with patch('auth_middleware.project_guard.jwt.decode', return_value=payload):
                with patch('auth_middleware.project_guard.get_redis', new_callable=AsyncMock, return_value=mock_redis):
                    with pytest.raises(Exception, match="Token has been revoked"):
                        await middleware.authenticate(mock_request)

    @pytest.mark.asyncio
    async def test_platform_token_invalid_structure(self, middleware, mock_request):
        """Platform token fails with missing tenant_id"""
        payload = _base_platform_payload(tenant_id='')
        token = _make_token(payload)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        with patch.object(middleware, '_get_public_key_from_cache', new_callable=AsyncMock, return_value='mock_key'):
            with patch('auth_middleware.project_guard.jwt.decode', return_value=payload):
                with pytest.raises(Exception, match="Invalid platform token structure"):
                    await middleware.authenticate(mock_request)

    # ── Project token ────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_project_token_injects_project_context(self, middleware, mock_request):
        """Project token sets req.project with tenant_id, enabled_services, etc."""
        payload = _base_project_payload()
        token = _make_token(payload)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        mock_redis = AsyncMock()
        mock_redis.client = MagicMock()
        mock_redis.client.exists.return_value = 1
        mock_redis.get = AsyncMock(return_value=None)  # no cached secret version

        with patch.object(middleware, '_get_public_key_from_cache', new_callable=AsyncMock, return_value='mock_key'):
            with patch('auth_middleware.project_guard.jwt.decode', return_value=payload):
                with patch('auth_middleware.project_guard.get_redis', new_callable=AsyncMock, return_value=mock_redis):
                    with patch('auth_middleware.project_guard.generate_token', new_callable=AsyncMock, return_value='svc-access-token'):
                        with patch('auth_middleware.project_guard.get_service_by_id', new_callable=AsyncMock, return_value='svc-uuid-1'):
                            await middleware.authenticate(mock_request)

        assert mock_request.project is not None
        assert mock_request.project.tenant_id == 'tenant-xyz'
        assert mock_request.project.enabled_services == ['svc-uuid-1', 'svc-uuid-2']
        assert mock_request.project.scopes == ['posts:read']
        assert mock_request.project.secret_version == 1

    @pytest.mark.asyncio
    async def test_project_token_service_not_enabled(self, middleware, mock_request):
        """Project token fails when our service UUID is not in enabled_services"""
        payload = _base_project_payload(enabled_services=['other-svc'])
        token = _make_token(payload)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        mock_redis = AsyncMock()
        mock_redis.client = MagicMock()
        mock_redis.client.exists.return_value = 1
        mock_redis.get = AsyncMock(return_value=None)

        with patch.object(middleware, '_get_public_key_from_cache', new_callable=AsyncMock, return_value='mock_key'):
            with patch('auth_middleware.project_guard.jwt.decode', return_value=payload):
                with patch('auth_middleware.project_guard.get_redis', new_callable=AsyncMock, return_value=mock_redis):
                    with patch('auth_middleware.project_guard.generate_token', new_callable=AsyncMock, return_value='tok'):
                        with patch('auth_middleware.project_guard.get_service_by_id', new_callable=AsyncMock, return_value='my-svc-uuid'):
                            with pytest.raises(Exception, match="Service access denied"):
                                await middleware.authenticate(mock_request)

    @pytest.mark.asyncio
    async def test_project_token_outdated_secret_version(self, middleware, mock_request):
        """Project token fails when secret_version is outdated"""
        payload = _base_project_payload(secret_version=1)
        token = _make_token(payload)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        mock_redis = AsyncMock()
        mock_redis.client = MagicMock()
        mock_redis.client.exists.return_value = 1
        # Return a higher secret version from Redis
        mock_redis.get = AsyncMock(return_value=5)

        with patch.object(middleware, '_get_public_key_from_cache', new_callable=AsyncMock, return_value='mock_key'):
            with patch('auth_middleware.project_guard.jwt.decode', return_value=payload):
                with patch('auth_middleware.project_guard.get_redis', new_callable=AsyncMock, return_value=mock_redis):
                    with pytest.raises(Exception, match="secret version outdated"):
                        await middleware.authenticate(mock_request)

    @pytest.mark.asyncio
    async def test_project_token_revoked(self, middleware, mock_request):
        """Project token fails when not found in Redis (revoked)"""
        payload = _base_project_payload()
        token = _make_token(payload)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        mock_redis = AsyncMock()
        mock_redis.client = MagicMock()
        mock_redis.client.exists.return_value = 0
        mock_redis.get = AsyncMock(return_value=None)

        with patch.object(middleware, '_get_public_key_from_cache', new_callable=AsyncMock, return_value='mock_key'):
            with patch('auth_middleware.project_guard.jwt.decode', return_value=payload):
                with patch('auth_middleware.project_guard.get_redis', new_callable=AsyncMock, return_value=mock_redis):
                    with pytest.raises(Exception, match="Token has been revoked"):
                        await middleware.authenticate(mock_request)

    # ── Service token ────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_service_token_injects_service_context(self, middleware, mock_request):
        """Service token sets req.service with client_id, scopes, etc."""
        payload = _base_service_payload()
        token = _make_token(payload)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        with patch.object(middleware, '_get_public_key_from_cache', new_callable=AsyncMock, return_value='mock_key'):
            with patch('auth_middleware.project_guard.jwt.decode', return_value=payload):
                await middleware.authenticate(mock_request)

        assert mock_request.service is not None
        assert mock_request.service.client_id == 'client-001'
        assert mock_request.service.service_name == 'analytics'
        assert mock_request.service.scopes == ['services:read', 'services:write']
        assert mock_request.service.token_id == 'jti-svc-1'
        assert mock_request.platform is None
        assert mock_request.project is None

    @pytest.mark.asyncio
    async def test_service_token_invalid_structure(self, middleware, mock_request):
        """Service token fails with missing client_id"""
        payload = _base_service_payload(client_id='')
        token = _make_token(payload)
        mock_request.request.headers = {'x-project-token': f'Bearer {token}'}

        with patch.object(middleware, '_get_public_key_from_cache', new_callable=AsyncMock, return_value='mock_key'):
            with patch('auth_middleware.project_guard.jwt.decode', return_value=payload):
                with pytest.raises(Exception, match="Invalid service token structure"):
                    await middleware.authenticate(mock_request)

    # ── JWKS endpoint routing ────────────────────────────────────

    def test_decode_jwt_payload_extracts_type_and_tenant(self, middleware):
        """_decode_jwt_payload returns type and tenant_id"""
        payload = _base_project_payload()
        token = _make_token(payload)
        decoded = middleware._decode_jwt_payload(token)
        assert decoded['type'] == 'project'
        assert decoded['tenant_id'] == 'tenant-xyz'

    def test_decode_jwt_header_extracts_kid(self, middleware):
        """_decode_jwt_header returns header with alg"""
        payload = _base_platform_payload()
        token = _make_token(payload)
        header = middleware._decode_jwt_header(token)
        assert header['alg'] == 'HS256'
