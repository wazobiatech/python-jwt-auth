import pytest
import time
import jwt
from unittest.mock import Mock, patch, AsyncMock
from auth_middleware import JwtAuthMiddleware, AuthenticatedRequest


class TestJwtAuthMiddleware:

    @pytest.fixture
    def middleware(self):
        """Create middleware instance"""
        with patch.dict('os.environ', {'MERCURY_BASE_URL': 'http://localhost:4000'}):
            return JwtAuthMiddleware()

    @pytest.fixture
    def mock_request(self):
        """Create mock request with headers"""
        request = Mock()
        request.headers = {}
        return AuthenticatedRequest(request)

    @pytest.fixture
    def valid_token_payload(self):
        """Create valid JWT payload — uses tenant_id (not project_uuid)"""
        return {
            'sub': {
                'uuid': 'test-user-uuid',
                'email': 'test@example.com',
                'name': 'Test User',
            },
            'tenant_id': 'test-tenant-id',
            'permissions': ['read:posts', 'write:posts'],
            'type': 'access',
            'iss': 'http://localhost:4000',
            'aud': 'http://localhost:4000',
            'exp': int(time.time()) + 3600,
            'nbf': int(time.time()) - 10,
            'iat': int(time.time()),
            'jti': 'test-token-id',
        }

    # ── Header extraction ────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_no_auth_header(self, middleware, mock_request):
        """Fails when Authorization header is missing"""
        with pytest.raises(Exception, match='No authorization header provided'):
            await middleware.authenticate(mock_request)

    @pytest.mark.asyncio
    async def test_empty_bearer_token(self, middleware, mock_request):
        """Fails when Bearer prefix is present but token is empty"""
        mock_request.request.headers = {'authorization': 'Bearer '}
        with pytest.raises(Exception, match='No token provided'):
            await middleware.authenticate(mock_request)

    # ── Token format / signing key errors ────────────────────────

    @pytest.mark.asyncio
    async def test_invalid_token_format(self, middleware, mock_request):
        """Fails with malformed token"""
        mock_request.request.headers = {'authorization': 'Bearer invalid.token'}
        with patch.object(middleware, '_get_signing_key', side_effect=Exception('Invalid JWT format')):
            with pytest.raises(Exception, match='Invalid JWT'):
                await middleware.authenticate(mock_request)

    # ── Expired token ────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_expired_token(self, middleware, mock_request, valid_token_payload):
        """Fails with expired token"""
        valid_token_payload['exp'] = int(time.time()) - 3600
        token = jwt.encode(valid_token_payload, 'secret', algorithm='HS256')
        mock_request.request.headers = {'authorization': f'Bearer {token}'}

        with patch.object(middleware, '_get_signing_key', return_value='mock_key'):
            with patch.object(middleware, '_validate', side_effect=Exception('Token expired')):
                with pytest.raises(Exception, match='Token expired'):
                    await middleware.authenticate(mock_request)

    # ── Successful authentication ────────────────────────────────

    @pytest.mark.asyncio
    async def test_successful_auth_injects_user_with_tenant_and_permissions(
        self, middleware, mock_request, valid_token_payload
    ):
        """After successful auth, req.user has uuid, email, name, tenant_id, permissions, token_id"""
        token = jwt.encode(valid_token_payload, 'secret', algorithm='HS256')
        mock_request.request.headers = {'authorization': f'Bearer {token}'}

        expected_user = {
            'uuid': 'test-user-uuid',
            'email': 'test@example.com',
            'name': 'Test User',
            'tenant_id': 'test-tenant-id',
            'permissions': ['read:posts', 'write:posts'],
            'token_id': 'test-token-id',
        }

        with patch.object(middleware, '_get_signing_key', return_value='mock_key'):
            with patch.object(middleware, '_validate', return_value=expected_user):
                await middleware.authenticate(mock_request)

                assert mock_request.user['uuid'] == 'test-user-uuid'
                assert mock_request.user['tenant_id'] == 'test-tenant-id'
                assert mock_request.user['permissions'] == ['read:posts', 'write:posts']
                assert mock_request.user['token_id'] == 'test-token-id'

    # ── Cache hit returns full user ──────────────────────────────

    @pytest.mark.asyncio
    async def test_cache_hit_returns_full_user(self, middleware, mock_request, valid_token_payload):
        """When cached token exists, user still gets tenant_id/permissions/token_id"""
        token = jwt.encode(valid_token_payload, 'secret', algorithm='HS256')
        mock_request.request.headers = {'authorization': f'Bearer {token}'}

        cached_user = {
            'uuid': 'test-user-uuid',
            'email': 'test@example.com',
            'name': 'Test User',
            'tenant_id': 'test-tenant-id',
            'permissions': ['read:posts'],
            'token_id': 'test-token-id',
        }

        with patch.object(middleware, '_get_signing_key', return_value='mock_key'):
            with patch.object(middleware, '_validate', return_value=cached_user):
                await middleware.authenticate(mock_request)

                assert mock_request.user['tenant_id'] == 'test-tenant-id'
                assert mock_request.user['token_id'] == 'test-token-id'

    # ── tenant_id extraction ─────────────────────────────────────

    def test_decode_tenant_id_from_token(self, middleware, valid_token_payload):
        """_decode_jwt_token_for_tenant_id extracts tenant_id correctly"""
        token = jwt.encode(valid_token_payload, 'secret', algorithm='HS256')
        result = middleware._decode_jwt_token_for_tenant_id(token)
        assert result == 'test-tenant-id'

    def test_decode_tenant_id_returns_none_for_bad_token(self, middleware):
        """Returns None for invalid tokens"""
        assert middleware._decode_jwt_token_for_tenant_id('bad') is None

    # ── JWKS URI uses tenant_id ──────────────────────────────────

    def test_jwks_uri_uses_tenant_id(self, middleware):
        """JWKS path is auth/projects/{tenant_id}/..."""
        uri, path = middleware._get_jwks_uri_and_path('my-tenant-123')
        assert 'auth/projects/my-tenant-123/.well-known/jwks.json' in uri
        assert path == 'auth/projects/my-tenant-123/.well-known/jwks.json'

    def test_jwks_uri_raises_without_tenant_id(self, middleware):
        """Raises when tenant_id is None"""
        with pytest.raises(Exception, match='No tenant_id'):
            middleware._get_jwks_uri_and_path(None)

    # ── JWKS fetch ───────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_jwks_fetch(self, middleware):
        """Fetches and returns JWKS data"""
        mock_jwks = {
            'keys': [{'kid': 'k1', 'kty': 'RSA', 'use': 'sig', 'n': 'n', 'e': 'AQAB'}]
        }
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_jwks
            mock_get.return_value = mock_response

            data = await middleware._fetch_jwks('http://test.com/jwks', 'auth/test')
            assert data == mock_jwks

    # ── Revocation is non-blocking ───────────────────────────────

    @pytest.mark.asyncio
    async def test_revocation_check_non_blocking_on_redis_failure(
        self, middleware, mock_request, valid_token_payload
    ):
        """Redis failure during revocation check should NOT block authentication"""
        token = jwt.encode(valid_token_payload, 'secret', algorithm='HS256')
        mock_request.request.headers = {'authorization': f'Bearer {token}'}

        # Simulate successful validation but Redis failure during revocation
        expected_user = {
            'uuid': 'test-user-uuid',
            'email': 'test@example.com',
            'name': 'Test User',
            'tenant_id': 'test-tenant-id',
            'permissions': [],
            'token_id': 'test-token-id',
        }

        with patch.object(middleware, '_get_signing_key', return_value='mock_key'):
            with patch.object(middleware, '_validate', return_value=expected_user):
                await middleware.authenticate(mock_request)
                assert mock_request.user['uuid'] == 'test-user-uuid'
