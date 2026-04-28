import os
import asyncio
import redis
from typing import Optional, Any, Dict
import json
import logging

logger = logging.getLogger(__name__)


class RedisConnectionManager:
    """Singleton Redis connection manager.

    The underlying ``redis-py`` client is synchronous; the async wrappers
    below offload calls to a worker thread via ``asyncio.to_thread`` so they
    do not block the event loop.
    """
    _instance: Optional['RedisConnectionManager'] = None
    _client: Optional[redis.Redis] = None

    def __new__(cls) -> 'RedisConnectionManager':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.initialized = True
            self._connect()

    def _connect(self) -> None:
        """Initialize Redis connection"""
        try:
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            self._client = redis.from_url(
                redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            # Test connection
            self._client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.error(f"Redis connection error: {e}")
            raise Exception(f"Redis connection error: {e}")

    @classmethod
    def get_instance(cls) -> 'RedisConnectionManager':
        """Get singleton instance"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def client(self) -> redis.Redis:
        """Get Redis client"""
        if self._client is None:
            self._connect()
        return self._client

    async def get(self, key: str) -> Optional[Any]:
        """Get value from Redis (returns parsed JSON if value is JSON, else raw)."""
        try:
            value = await asyncio.to_thread(self.client.get, key)
            if value:
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return value
            return None
        except Exception as e:
            logger.warning(f"Redis get error for key {key}: {e}")
            return None

    async def set(self, key: str, value: Any, options: Optional[Dict[str, Any]] = None) -> bool:
        """Set value in Redis with optional expiry"""
        try:
            if not isinstance(value, str):
                value = json.dumps(value)

            if options and 'EX' in options:
                return bool(await asyncio.to_thread(self.client.setex, key, options['EX'], value))
            return bool(await asyncio.to_thread(self.client.set, key, value))
        except Exception as e:
            logger.warning(f"Redis set error for key {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete key from Redis"""
        try:
            return bool(await asyncio.to_thread(self.client.delete, key))
        except Exception as e:
            logger.warning(f"Redis delete error for key {key}: {e}")
            return False

    async def exists(self, key: str) -> bool:
        """
        Return True if ``key`` exists in Redis.

        Raises on connection / command errors so callers can apply their own
        fail-open / fail-closed policy explicitly.
        """
        return bool(await asyncio.to_thread(self.client.exists, key))

    def close(self) -> None:
        """Close Redis connection"""
        if self._client:
            self._client.close()
            self._client = None
            logger.info("Redis connection closed")

    def __del__(self):
        """Cleanup on deletion"""
        self.close()


# Convenience function for getting Redis instance
async def get_redis() -> RedisConnectionManager:
    """Get Redis connection manager instance"""
    return RedisConnectionManager.get_instance()
