import pytest
from unittest.mock import Mock, patch, AsyncMock
from auth_middleware import ProjectAuthMiddleware, AuthenticatedRequest


class TestProjectAuthMiddleware:
    
    @pytest.fixture
    def middleware(self):
        """Create middleware instance"""
        return ProjectAuthMiddleware()
    
    @pytest.fixture
    def mock_request(self):
        """Create mock request with headers"""
        request = Mock()
        request.headers = {}
        return AuthenticatedRequest(request)
    
    @pytest.mark.asyncio
    async def test_missing_headers(self, middleware, mock_request):
        """Test authentication fails without required headers"""
        with pytest.raises(Exception) as exc_info:
            await middleware.authenticate(mock_request)
        
        assert 'Missing API key' in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_successful_authentication(self, middleware, mock_request):
        """Test successful project authentication"""
        mock_request.headers['x-app-id'] = 'test-app-id'
        mock_request.headers['x-app-secret'] = 'test-secret'
        
        expected_project = {
            'projectUuid': 'test-project-uuid',
            'projectName': 'Test Project'
        }
        
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None  # Cache miss
        
        with patch('auth_middleware.project_guard.get_redis', return_value=mock_redis):
            with patch.object(middleware, '_verify_with_athens', return_value=expected_project):
                await middleware.authenticate(mock_request)
                
                assert mock_request.project == expected_project
    
    @pytest.mark.asyncio
    async def test_cache_hit(self, middleware, mock_request):
        """Test project authentication with cache hit"""
        mock_request.headers['x-app-id'] = 'test-app-id'
        mock_request.headers['x-app-secret'] = 'test-secret'
        
        cached_project = {
            'projectUuid': 'cached-project-uuid',
            'projectName': 'Cached Project'
        }
        
        mock_redis = AsyncMock()
        mock_redis.get.return_value = cached_project
        
        with patch('auth_middleware.project_guard.get_redis', return_value=mock_redis):
            await middleware.authenticate(mock_request)
            
            assert mock_request.project == cached_project
    
    @pytest.mark.asyncio
    async def test_athens_verification_failure(self, middleware, mock_request):
        """Test handling of Athens verification failure"""
        mock_request.headers['x-app-id'] = 'invalid-app-id'
        mock_request.headers['x-app-secret'] = 'invalid-secret'
        
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None  # Cache miss
        
        with patch('auth_middleware.project_guard.get_redis', return_value=mock_redis):
            with patch('requests.get') as mock_get:
                mock_response = Mock()
                mock_response.status_code = 401
                mock_response.json.return_value = {'error': 'Invalid credentials'}
                mock_response.text = 'Invalid credentials'
                mock_get.return_value = mock_response
                
                with pytest.raises(Exception) as exc_info:
                    await middleware.authenticate(mock_request)
                
                assert 'Invalid API credentials' in str(exc_info.value)