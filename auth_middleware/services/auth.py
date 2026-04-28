# auth_middleware/services/auth.py
"""
Service authentication helpers — mirrors Node services/auth.ts.

- generate_token(): client-credentials flow via Mercury GraphQL, cached in
  Redis (~55 min) and in-process for the life of the process.
- get_service_by_id(): resolve service UUID by client_id, cached in Redis
  (~24 hr) and in-process for the life of the process.
- clear_cache(): invalidate Redis caches and the in-process layer.

Caching layers
--------------
Mercury is on the auth path for every cold project-token request. To avoid
making it a hard dependency we layer two caches:

1. **In-process** — a module-level dict keyed by ``client_id`` with its own
   expiry timestamp. The first request after a deploy fills it; every later
   request in the same process returns instantly without touching Redis or
   Mercury. The service UUID rarely changes, so a 24h TTL is safe.
2. **Redis** — survives process restarts and is shared across replicas.

A Mercury outage now only affects requests that miss both layers.
"""
import os
import time
import asyncio
import logging
from typing import Optional, Dict, Tuple

from ..utils.redis_connection import get_redis
from .graphql_client import (
    create_graphql_client,
    GENERATE_SERVICE_TOKEN,
    GET_REGISTERED_SERVICE_BY_CLIENT_ID,
)

logger = logging.getLogger(__name__)

# Cache TTL constants (seconds) — mirror Node/Laravel values
SERVICE_TOKEN_TTL = int(os.getenv('SERVICE_TOKEN_CACHE_TTL', '3300'))   # ~55 min
SERVICE_UUID_TTL  = int(os.getenv('SERVICE_UUID_CACHE_TTL', '86400'))   # 24 hr

# In-process caches: { client_id: (value, expiry_unix_ts) }.
# Guarded by a per-coroutine lock so concurrent cache misses do not stampede
# Mercury.
_token_cache: Dict[str, Tuple[str, float]] = {}
_uuid_cache: Dict[str, Tuple[str, float]] = {}
_token_lock = asyncio.Lock()
_uuid_lock = asyncio.Lock()


def _get_required_env(key: str) -> str:
    value = os.getenv(key)
    if not value:
        raise Exception(f"Missing required environment variable: {key}")
    return value


def _inproc_get(cache: Dict[str, Tuple[str, float]], key: str) -> Optional[str]:
    entry = cache.get(key)
    if entry is None:
        return None
    value, expires_at = entry
    if expires_at <= time.time():
        cache.pop(key, None)
        return None
    return value


def _inproc_set(cache: Dict[str, Tuple[str, float]], key: str, value: str, ttl: int) -> None:
    cache[key] = (value, time.time() + ttl)


# ─────────────────────────────────────────────
# generate_token
# ─────────────────────────────────────────────

async def generate_token() -> str:
    """
    Generate a service token via Mercury GraphQL (client credentials flow).

    Looked up first in the in-process cache, then Redis, then Mercury. Result
    is cached in both layers for ~55 minutes.

    Returns:
        The service access token string.
    """
    client_id = _get_required_env('CLIENT_ID')
    client_secret = _get_required_env('CLIENT_SECRET')
    mercury_base_url = _get_required_env('MERCURY_BASE_URL')

    # Layer 1: in-process
    cached = _inproc_get(_token_cache, client_id)
    if cached:
        logger.debug('[ServiceAuth] in-proc service-token cache hit')
        return cached

    async with _token_lock:
        # Re-check after acquiring the lock — another coroutine may have
        # filled the cache while we were waiting.
        cached = _inproc_get(_token_cache, client_id)
        if cached:
            return cached

        cache_key = f"service_token:{client_id}"
        redis = await get_redis()

        # Layer 2: Redis
        cached_token = await redis.get(cache_key)
        if cached_token:
            token_str = str(cached_token)
            _inproc_set(_token_cache, client_id, token_str, SERVICE_TOKEN_TTL)
            logger.debug('[ServiceAuth] redis service-token cache hit')
            return token_str

        logger.debug('[ServiceAuth] generating new service token from Mercury')

        client = create_graphql_client(f"{mercury_base_url}/graphql")
        data = await client.mutate_async(
            mutation=GENERATE_SERVICE_TOKEN,
            variables={
                'input': {
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'scope': 'services:read',
                }
            },
        )

        token_data = data.get('generateServiceToken')
        if not token_data or not token_data.get('access_token'):
            raise Exception('No data returned from generateServiceToken')

        access_token: str = token_data['access_token']

        await redis.set(cache_key, access_token, {'EX': SERVICE_TOKEN_TTL})
        _inproc_set(_token_cache, client_id, access_token, SERVICE_TOKEN_TTL)
        logger.debug('[ServiceAuth] service token cached')

        return access_token


# ─────────────────────────────────────────────
# get_service_by_id
# ─────────────────────────────────────────────

async def get_service_by_id(access_token: str) -> str:
    """
    Fetch the service UUID from Mercury using the service access token.

    Looked up first in the in-process cache, then Redis, then Mercury. Result
    is cached in both layers for ~24 hours. The service UUID is constant
    per deployment, so a Mercury outage after the first request is invisible
    until the cache expires.
    """
    client_id = _get_required_env('CLIENT_ID')
    mercury_base_url = _get_required_env('MERCURY_BASE_URL')

    # Layer 1: in-process
    cached = _inproc_get(_uuid_cache, client_id)
    if cached:
        logger.debug('[ServiceAuth] in-proc service-uuid cache hit')
        return cached

    async with _uuid_lock:
        cached = _inproc_get(_uuid_cache, client_id)
        if cached:
            return cached

        cache_key = f"service_uuid:{client_id}"
        redis = await get_redis()

        # Layer 2: Redis
        cached_uuid = await redis.get(cache_key)
        if cached_uuid:
            uuid_str = str(cached_uuid)
            _inproc_set(_uuid_cache, client_id, uuid_str, SERVICE_UUID_TTL)
            logger.debug('[ServiceAuth] redis service-uuid cache hit')
            return uuid_str

        logger.debug('[ServiceAuth] fetching service UUID from Mercury')

        client = create_graphql_client(
            f"{mercury_base_url}/graphql",
            headers={'x-project-token': f"Bearer {access_token}"},
        )
        data = await client.mutate_async(
            mutation=GET_REGISTERED_SERVICE_BY_CLIENT_ID,
            variables={'input': {'client_id': client_id}},
        )

        service_data = data.get('getRegisteredServiceByClientId')
        if not service_data or not service_data.get('uuid'):
            raise Exception('No data returned from getRegisteredServiceByClientId')

        service_uuid: str = service_data['uuid']

        await redis.set(cache_key, service_uuid, {'EX': SERVICE_UUID_TTL})
        _inproc_set(_uuid_cache, client_id, service_uuid, SERVICE_UUID_TTL)
        logger.debug('[ServiceAuth] service UUID cached')

        return service_uuid


# ─────────────────────────────────────────────
# clear_cache
# ─────────────────────────────────────────────

async def clear_cache() -> None:
    """Clear cached service token and UUID from Redis and the in-process cache."""
    client_id = _get_required_env('CLIENT_ID')
    redis = await get_redis()

    token_key = f"service_token:{client_id}"
    uuid_key = f"service_uuid:{client_id}"

    await redis.delete(token_key)
    await redis.delete(uuid_key)
    _token_cache.pop(client_id, None)
    _uuid_cache.pop(client_id, None)
    logger.info('[ServiceAuth] Service authentication cache cleared',
                extra={'keys_cleared': [token_key, uuid_key]})
