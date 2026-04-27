# auth_middleware/services/auth.py
"""
Service authentication helpers — mirrors Node services/auth.ts.

- generate_token(): client-credentials flow via Mercury GraphQL, cached ~55 min
- get_service_by_id(): resolve service UUID by client_id, cached ~24 hr
- clear_cache(): invalidate both caches
"""
import os
import logging
from typing import Optional

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


def _get_required_env(key: str) -> str:
    value = os.getenv(key)
    if not value:
        raise Exception(f"Missing required environment variable: {key}")
    return value


# ─────────────────────────────────────────────
# generate_token
# ─────────────────────────────────────────────

async def generate_token() -> str:
    """
    Generate a service token via Mercury GraphQL (client credentials flow).
    Result is cached in Redis for ~55 minutes.

    Returns:
        The service access token string.
    """
    client_id = _get_required_env('CLIENT_ID')
    client_secret = _get_required_env('CLIENT_SECRET')
    mercury_base_url = _get_required_env('MERCURY_BASE_URL')

    cache_key = f"service_token:{client_id}"

    # Check Redis cache first
    redis = await get_redis()
    cached_token = await redis.get(cache_key)
    if cached_token:
        logger.debug('[ServiceAuth] Using cached service token')
        return str(cached_token)

    logger.debug('[ServiceAuth] Generating new service token from Mercury')

    client = create_graphql_client(f"{mercury_base_url}/graphql")
    data = client.mutate(
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

    # Cache in Redis
    await redis.set(cache_key, access_token, {'EX': SERVICE_TOKEN_TTL})
    logger.debug('[ServiceAuth] Service token cached successfully')

    return access_token


# ─────────────────────────────────────────────
# get_service_by_id
# ─────────────────────────────────────────────

async def get_service_by_id(access_token: str) -> str:
    """
    Fetch the service UUID from Mercury using the service access token.
    Result is cached in Redis for ~24 hours.

    Args:
        access_token: A valid service access token.

    Returns:
        The UUID of the registered service.
    """
    client_id = _get_required_env('CLIENT_ID')
    mercury_base_url = _get_required_env('MERCURY_BASE_URL')

    cache_key = f"service_uuid:{client_id}"

    # Check Redis cache first
    redis = await get_redis()
    cached_uuid = await redis.get(cache_key)
    if cached_uuid:
        logger.debug('[ServiceAuth] Using cached service UUID')
        return str(cached_uuid)

    logger.debug('[ServiceAuth] Fetching service UUID from Mercury')

    client = create_graphql_client(
        f"{mercury_base_url}/graphql",
        headers={'x-project-token': f"Bearer {access_token}"},
    )
    data = client.mutate(
        mutation=GET_REGISTERED_SERVICE_BY_CLIENT_ID,
        variables={'input': {'client_id': client_id}},
    )

    service_data = data.get('getRegisteredServiceByClientId')
    if not service_data or not service_data.get('uuid'):
        raise Exception('No data returned from getRegisteredServiceByClientId')

    service_uuid: str = service_data['uuid']

    # Cache in Redis (longer TTL — rarely changes)
    await redis.set(cache_key, service_uuid, {'EX': SERVICE_UUID_TTL})
    logger.debug('[ServiceAuth] Service UUID cached successfully')

    return service_uuid


# ─────────────────────────────────────────────
# clear_cache
# ─────────────────────────────────────────────

async def clear_cache() -> None:
    """Clear cached service token and UUID from Redis."""
    client_id = _get_required_env('CLIENT_ID')
    redis = await get_redis()

    token_key = f"service_token:{client_id}"
    uuid_key = f"service_uuid:{client_id}"

    await redis.delete(token_key)
    await redis.delete(uuid_key)
    logger.info('[ServiceAuth] Service authentication cache cleared',
                extra={'keys_cleared': [token_key, uuid_key]})
