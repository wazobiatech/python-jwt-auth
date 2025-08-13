import pytest
import json
import time
import jwt
from unittest.mock import Mock, patch, AsyncMock
from auth_middleware import JwtAuthMiddleware, AuthenticatedRequest


class TestJwtAuthMiddleware:
    
    @pytest.fixture
    def middleware(self):
        """Create middleware instance"""
        return JwtAuthMiddleware()
    
    @pytest.fixture
    def mock_request(self):
        """Create mock request with headers"""
        request = Mock()
        request.headers = {}
        return AuthenticatedRequest(request)
    
    @pytest.fixture
    def valid_token_payload(self):
        """Create valid JWT payload"""
        return {
            'sub': {
                'uuid': 'test-user-uuid',
                'email': 'test@example.com',
                'name': 'Test User'
            },
            'project_uuid': 'test-project',
            'type': 'access',
            'iss': 'http://localhost:4000',
            'aud': 'http://localhost:4000',
            'exp': int(time.time()) + 3600,
            'nbf': int(time.time()) - 10,
            'iat': int(time.time()),
            'jti': 'test-token-id'
        }
    
    @pytest.mark.asyncio
    async def test_no_auth_header(self, middleware, mock_request):
        """Test authentication fails without authorization header"""
        with pytest.raises(Exception) as exc_info:
            await middleware.authenticate(mock_request)
        
        assert 'No authorization header provided' in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_invalid_token_format(self, middleware, mock_request):
        """Test authentication fails with invalid token format"""
        mock_request.headers['authorization'] = 'Bearer invalid.token'
        
        with patch.object(middleware, '_get_signing_key', side_effect=Exception('Invalid JWT format')):
            with pytest.raises(Exception) as exc_info:
                await middleware.authenticate(mock_request)
            
            assert 'Invalid JWT' in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_expired_token(self, middleware, mock_request, valid_token_payload):
        """Test authentication fails with expired token"""
        # Create expired token
        valid_token_payload['exp'] = int(time.time()) - 3600
        
        # Create token
        token = jwt.encode(valid_token_payload, 'secret', algorithm='HS256')
        mock_request.headers['authorization'] = f'Bearer {token}'
        
        with patch.object(middleware, '_get_signing_key', return_value='mock_key'):
            with patch.object(middleware, '_validate', side_effect=Exception('Token expired')):
                with pytest.raises(Exception) as exc_info:
                    await middleware.authenticate(mock_request)
                
                assert 'Token expired' in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_successful_authentication(self, middleware, mock_request, valid_token_payload):
        """Test successful JWT authentication"""
        token = jwt.encode(valid_token_payload, 'secret', algorithm='HS256')
        mock_request.headers['authorization'] = f'Bearer {token}'
        
        expected_user = {
            'uuid': 'test-user-uuid',
            'email': 'test@example.com',
            'name': 'Test User'
        }
        
        with patch.object(middleware, '_get_signing_key', return_value='mock_key'):
            with patch.object(middleware, '_validate', return_value=expected_user):
                await middleware.authenticate(mock_request)
                
                assert mock_request.user == expected_user
    
    @pytest.mark.asyncio
    async def test_cache_hit(self, middleware, mock_request, valid_token_payload):
        """Test token validation with cache hit"""
        token = jwt.encode(valid_token_payload, 'secret', algorithm='HS256')
        mock_request.headers['authorization'] = f'Bearer {token}'
        
        mock_redis = AsyncMock()
        mock_redis.get.return_value = valid_token_payload
        
        with patch('auth_middleware.jwt_guard.get_redis', return_value=mock_redis):
            with patch.object(middleware, '_get_signing_key', return_value='mock_key'):
                with patch.object(middleware, '_get_cached_token', return_value=valid_token_payload):
                    await middleware.authenticate(mock_request)
                    
                    assert mock_request.user['uuid'] == 'test-user-uuid'
    
    @pytest.mark.asyncio
    async def test_jwks_fetch_and_cache(self, middleware):
        """Test JWKS fetching and caching"""
        mock_jwks = {
            'keys': [
                {
                    'kid': 'test-key-id',
                    'kty': 'RSA',
                    'use': 'sig',
                    'n': 'mock_n_value',
                    'e': 'AQAB'
                }
            ]
        }
        
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_jwks
            mock_get.return_value = mock_response
            
            jwks_data = await middleware._fetch_jwks('http://test.com/jwks')
            
            assert jwks_data == mock_jwks
            mock_get.assert_called_once()

