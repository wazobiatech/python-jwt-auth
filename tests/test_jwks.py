"""
Tests for JWKS handling in ProjectAuthMiddleware.

Covers:
- HMAC signature construction on the JWKS fetch
- Auto-refresh when a kid is missing from the cached JWKS
- Service vs. tenant-scoped JWKS endpoint routing
- tenant_id validation in cache keys
"""
import json
import hmac
import hashlib
import time as time_mod
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from auth_middleware.project_guard import ProjectAuthMiddleware


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv('MERCURY_BASE_URL', 'http://mercury.test')
    monkeypatch.setenv('SIGNATURE_SHARED_SECRET', 'shared-secret')


@pytest.fixture
def middleware():
    return ProjectAuthMiddleware('test-service')


@pytest.fixture
def fake_jwks():
    return {
        'keys': [
            {'kid': 'kid-A', 'kty': 'RSA', 'use': 'sig', 'n': 'AQ', 'e': 'AQAB'},
            {'kid': 'kid-B', 'kty': 'RSA', 'use': 'sig', 'n': 'AQ', 'e': 'AQAB'},
        ]
    }


# ─────────────────────────────────────────────
# HMAC signature
# ─────────────────────────────────────────────

class TestJwksFetchHmac:

    @pytest.mark.asyncio
    async def test_signature_uses_method_path_timestamp(self, middleware, fake_jwks):
        """X-Signature is HMAC-SHA256 of GET + path + timestamp using SIGNATURE_SHARED_SECRET."""
        captured_headers = {}

        def fake_get(url, headers=None, timeout=None):
            captured_headers.update(headers or {})
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = fake_jwks
            return mock_response

        mock_redis = AsyncMock()
        mock_redis.set = AsyncMock(return_value=True)

        with patch('auth_middleware.project_guard.requests.get', side_effect=fake_get), \
             patch('auth_middleware.project_guard.get_redis', new_callable=AsyncMock, return_value=mock_redis):
            await middleware._fetch_and_cache_jwks('auth/projects/t1/.well-known/jwks.json', 'jwks_cache:t1')

        ts = captured_headers['X-Timestamp']
        expected_sig = hmac.new(
            b'shared-secret',
            f"GET/auth/projects/t1/.well-known/jwks.json{ts}".encode(),
            hashlib.sha256,
        ).hexdigest()
        assert captured_headers['X-Signature'] == expected_sig
        assert captured_headers['User-Agent'].startswith('Mercury-Auth-SDK')

    @pytest.mark.asyncio
    async def test_non_200_raises(self, middleware):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = 'boom'

        with patch('auth_middleware.project_guard.requests.get', return_value=mock_response):
            with pytest.raises(Exception, match='HTTP 500'):
                await middleware._fetch_and_cache_jwks('auth/x', 'k')

    @pytest.mark.asyncio
    async def test_invalid_jwks_response_raises(self, middleware):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'foo': 'bar'}  # missing 'keys'

        with patch('auth_middleware.project_guard.requests.get', return_value=mock_response):
            with pytest.raises(Exception, match='Invalid JWKS response'):
                await middleware._fetch_and_cache_jwks('auth/x', 'k')


# ─────────────────────────────────────────────
# Auto-refresh on cached-but-missing kid
# ─────────────────────────────────────────────

class TestJwksAutoRefresh:

    @pytest.mark.asyncio
    async def test_refresh_when_kid_not_in_cached_jwks(self, middleware, fake_jwks):
        """A token referencing kid-C should trigger a re-fetch when only kid-A/B are cached."""
        # Token header has kid-C
        token_header = {'alg': 'RS512', 'typ': 'JWT', 'kid': 'kid-C'}
        token_payload = {'type': 'project', 'tenant_id': 'tenant-A'}

        # Refreshed JWKS adds kid-C
        refreshed = {
            'keys': fake_jwks['keys'] + [{'kid': 'kid-C', 'kty': 'RSA', 'n': 'AQ', 'e': 'AQAB'}]
        }

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=fake_jwks)  # cached, but missing kid-C

        with patch.object(middleware, '_decode_jwt_header', return_value=token_header), \
             patch.object(middleware, '_decode_jwt_payload', return_value=token_payload), \
             patch.object(middleware, '_fetch_and_cache_jwks', new_callable=AsyncMock, return_value=refreshed) as mock_fetch, \
             patch.object(middleware, '_find_key_in_jwks', side_effect=[None, 'pem-for-kid-C']) as mock_find, \
             patch('auth_middleware.project_guard.get_redis', new_callable=AsyncMock, return_value=mock_redis):
            pem = await middleware._get_public_key_from_cache('dummy.token.value')

        assert pem == 'pem-for-kid-C'
        mock_fetch.assert_awaited_once_with('auth/projects/tenant-A/.well-known/jwks.json', 'jwks_cache:tenant-A')
        # First find call against cached JWKS, second against the refreshed JWKS
        assert mock_find.call_count == 2

    @pytest.mark.asyncio
    async def test_kid_still_missing_after_refresh_raises(self, middleware, fake_jwks):
        token_header = {'alg': 'RS512', 'typ': 'JWT', 'kid': 'kid-MISSING'}
        token_payload = {'type': 'project', 'tenant_id': 'tenant-A'}

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=fake_jwks)

        with patch.object(middleware, '_decode_jwt_header', return_value=token_header), \
             patch.object(middleware, '_decode_jwt_payload', return_value=token_payload), \
             patch.object(middleware, '_fetch_and_cache_jwks', new_callable=AsyncMock, return_value=fake_jwks), \
             patch.object(middleware, '_find_key_in_jwks', return_value=None), \
             patch('auth_middleware.project_guard.get_redis', new_callable=AsyncMock, return_value=mock_redis):
            with pytest.raises(Exception, match='Failed to get public key'):
                await middleware._get_public_key_from_cache('dummy.token.value')


# ─────────────────────────────────────────────
# Endpoint routing & tenant_id validation
# ─────────────────────────────────────────────

class TestJwksEndpointRouting:

    @pytest.mark.asyncio
    async def test_service_token_uses_service_jwks_endpoint(self, middleware, fake_jwks):
        token_header = {'alg': 'RS512', 'typ': 'JWT', 'kid': 'kid-A'}
        token_payload = {'type': 'service', 'client_id': 'c'}

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)  # nothing cached

        with patch.object(middleware, '_decode_jwt_header', return_value=token_header), \
             patch.object(middleware, '_decode_jwt_payload', return_value=token_payload), \
             patch.object(middleware, '_fetch_and_cache_jwks', new_callable=AsyncMock, return_value=fake_jwks) as mock_fetch, \
             patch.object(middleware, '_find_key_in_jwks', return_value='pem'), \
             patch('auth_middleware.project_guard.get_redis', new_callable=AsyncMock, return_value=mock_redis):
            await middleware._get_public_key_from_cache('dummy.token.value')

        mock_fetch.assert_awaited_once_with('auth/service/.well-known/jwks.json', 'service_jwks_cache')

    @pytest.mark.asyncio
    async def test_invalid_tenant_id_rejected(self, middleware):
        """A tenant_id with disallowed characters must be rejected."""
        token_header = {'alg': 'RS512', 'kid': 'k'}
        token_payload = {'type': 'project', 'tenant_id': 'evil:tenant'}

        with patch.object(middleware, '_decode_jwt_header', return_value=token_header), \
             patch.object(middleware, '_decode_jwt_payload', return_value=token_payload):
            with pytest.raises(Exception, match='Invalid or missing tenant_id'):
                await middleware._get_public_key_from_cache('dummy.token.value')

    @pytest.mark.asyncio
    async def test_missing_tenant_id_rejected(self, middleware):
        token_header = {'alg': 'RS512', 'kid': 'k'}
        token_payload = {'type': 'project', 'tenant_id': ''}

        with patch.object(middleware, '_decode_jwt_header', return_value=token_header), \
             patch.object(middleware, '_decode_jwt_payload', return_value=token_payload):
            with pytest.raises(Exception, match='Invalid or missing tenant_id'):
                await middleware._get_public_key_from_cache('dummy.token.value')

    @pytest.mark.asyncio
    async def test_unsupported_alg_rejected(self, middleware):
        """Header with non-RS512 alg is rejected up front."""
        token_header = {'alg': 'HS256', 'kid': 'k'}
        token_payload = {'type': 'project', 'tenant_id': 'tenant-A'}

        with patch.object(middleware, '_decode_jwt_header', return_value=token_header), \
             patch.object(middleware, '_decode_jwt_payload', return_value=token_payload):
            with pytest.raises(Exception, match='Unsupported alg'):
                await middleware._get_public_key_from_cache('dummy.token.value')
