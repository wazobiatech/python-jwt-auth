"""
Tests for auth_middleware/services/auth.py.

Covers the two-layer cache (in-process + Redis), Mercury fall-through, and
clear_cache. Each test resets the in-process cache so they are independent.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from auth_middleware.services import auth as svc_auth


@pytest.fixture(autouse=True)
def _reset_inproc_caches():
    """Reset the module-level in-process caches before/after each test."""
    svc_auth._token_cache.clear()
    svc_auth._uuid_cache.clear()
    yield
    svc_auth._token_cache.clear()
    svc_auth._uuid_cache.clear()


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv('CLIENT_ID', 'client-001')
    monkeypatch.setenv('CLIENT_SECRET', 'secret-xyz')
    monkeypatch.setenv('MERCURY_BASE_URL', 'http://mercury.test')


# ─────────────────────────────────────────────
# generate_token
# ─────────────────────────────────────────────

class TestGenerateToken:

    @pytest.mark.asyncio
    async def test_inproc_cache_hit_skips_redis_and_mercury(self):
        """In-process cache hit returns immediately without touching Redis or Mercury."""
        svc_auth._inproc_set(svc_auth._token_cache, 'client-001', 'inproc-token', 60)

        with patch('auth_middleware.services.auth.get_redis') as mock_get_redis, \
             patch('auth_middleware.services.auth.create_graphql_client') as mock_client:
            result = await svc_auth.generate_token()

        assert result == 'inproc-token'
        mock_get_redis.assert_not_called()
        mock_client.assert_not_called()

    @pytest.mark.asyncio
    async def test_redis_cache_hit_skips_mercury(self):
        """Redis cache hit returns the cached token and primes the in-process cache."""
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value='redis-token')

        with patch('auth_middleware.services.auth.get_redis', new_callable=AsyncMock, return_value=mock_redis), \
             patch('auth_middleware.services.auth.create_graphql_client') as mock_client:
            result = await svc_auth.generate_token()

        assert result == 'redis-token'
        mock_client.assert_not_called()
        # Second call should now hit the in-process cache
        assert svc_auth._inproc_get(svc_auth._token_cache, 'client-001') == 'redis-token'

    @pytest.mark.asyncio
    async def test_cache_miss_calls_mercury_and_caches_result(self):
        """On full cache miss, calls Mercury, stores in Redis + in-process."""
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.set = AsyncMock(return_value=True)

        mock_client = MagicMock()
        mock_client.mutate_async = AsyncMock(return_value={
            'generateServiceToken': {'access_token': 'fresh-token'}
        })

        with patch('auth_middleware.services.auth.get_redis', new_callable=AsyncMock, return_value=mock_redis), \
             patch('auth_middleware.services.auth.create_graphql_client', return_value=mock_client):
            result = await svc_auth.generate_token()

        assert result == 'fresh-token'
        mock_client.mutate_async.assert_awaited_once()
        mock_redis.set.assert_awaited_once()
        # In-process cache populated
        assert svc_auth._inproc_get(svc_auth._token_cache, 'client-001') == 'fresh-token'

    @pytest.mark.asyncio
    async def test_mercury_returns_no_data_raises(self):
        """Empty Mercury response surfaces a clear error."""
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)

        mock_client = MagicMock()
        mock_client.mutate_async = AsyncMock(return_value={'generateServiceToken': None})

        with patch('auth_middleware.services.auth.get_redis', new_callable=AsyncMock, return_value=mock_redis), \
             patch('auth_middleware.services.auth.create_graphql_client', return_value=mock_client):
            with pytest.raises(Exception, match='No data returned from generateServiceToken'):
                await svc_auth.generate_token()

    @pytest.mark.asyncio
    async def test_missing_env_raises(self, monkeypatch):
        """Missing CLIENT_ID raises a clear error."""
        monkeypatch.delenv('CLIENT_ID', raising=False)
        with pytest.raises(Exception, match='Missing required environment variable: CLIENT_ID'):
            await svc_auth.generate_token()


# ─────────────────────────────────────────────
# get_service_by_id
# ─────────────────────────────────────────────

class TestGetServiceById:

    @pytest.mark.asyncio
    async def test_inproc_cache_hit_skips_redis_and_mercury(self):
        svc_auth._inproc_set(svc_auth._uuid_cache, 'client-001', 'svc-uuid-cached', 60)

        with patch('auth_middleware.services.auth.get_redis') as mock_get_redis, \
             patch('auth_middleware.services.auth.create_graphql_client') as mock_client:
            result = await svc_auth.get_service_by_id('access-token')

        assert result == 'svc-uuid-cached'
        mock_get_redis.assert_not_called()
        mock_client.assert_not_called()

    @pytest.mark.asyncio
    async def test_redis_cache_hit_skips_mercury(self):
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value='redis-uuid')

        with patch('auth_middleware.services.auth.get_redis', new_callable=AsyncMock, return_value=mock_redis), \
             patch('auth_middleware.services.auth.create_graphql_client') as mock_client:
            result = await svc_auth.get_service_by_id('access-token')

        assert result == 'redis-uuid'
        mock_client.assert_not_called()
        assert svc_auth._inproc_get(svc_auth._uuid_cache, 'client-001') == 'redis-uuid'

    @pytest.mark.asyncio
    async def test_cache_miss_calls_mercury_with_auth_header(self):
        """On miss, Mercury is called with 'x-project-token: Bearer <access>'."""
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.set = AsyncMock(return_value=True)

        mock_client = MagicMock()
        mock_client.mutate_async = AsyncMock(return_value={
            'getRegisteredServiceByClientId': {'uuid': 'fresh-uuid'}
        })
        mock_create = MagicMock(return_value=mock_client)

        with patch('auth_middleware.services.auth.get_redis', new_callable=AsyncMock, return_value=mock_redis), \
             patch('auth_middleware.services.auth.create_graphql_client', mock_create):
            result = await svc_auth.get_service_by_id('access-token')

        assert result == 'fresh-uuid'
        # Verify the auth header was passed through
        _, kwargs = mock_create.call_args
        assert kwargs['headers'] == {'x-project-token': 'Bearer access-token'}

    @pytest.mark.asyncio
    async def test_mercury_returns_no_data_raises(self):
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)

        mock_client = MagicMock()
        mock_client.mutate_async = AsyncMock(return_value={'getRegisteredServiceByClientId': None})

        with patch('auth_middleware.services.auth.get_redis', new_callable=AsyncMock, return_value=mock_redis), \
             patch('auth_middleware.services.auth.create_graphql_client', return_value=mock_client):
            with pytest.raises(Exception, match='No data returned from getRegisteredServiceByClientId'):
                await svc_auth.get_service_by_id('access-token')


# ─────────────────────────────────────────────
# clear_cache
# ─────────────────────────────────────────────

class TestClearCache:

    @pytest.mark.asyncio
    async def test_clears_redis_and_inproc(self):
        """clear_cache wipes both Redis keys and in-process entries."""
        svc_auth._inproc_set(svc_auth._token_cache, 'client-001', 'tok', 60)
        svc_auth._inproc_set(svc_auth._uuid_cache, 'client-001', 'uuid', 60)

        mock_redis = AsyncMock()
        mock_redis.delete = AsyncMock(return_value=True)

        with patch('auth_middleware.services.auth.get_redis', new_callable=AsyncMock, return_value=mock_redis):
            await svc_auth.clear_cache()

        # Redis deletes called for both keys
        assert mock_redis.delete.await_count == 2
        delete_keys = [c.args[0] for c in mock_redis.delete.await_args_list]
        assert 'service_token:client-001' in delete_keys
        assert 'service_uuid:client-001' in delete_keys

        # In-process caches cleared
        assert svc_auth._inproc_get(svc_auth._token_cache, 'client-001') is None
        assert svc_auth._inproc_get(svc_auth._uuid_cache, 'client-001') is None
