# auth_middleware/project_guard.py
import os
import base64
import hmac
import hashlib
import time
import requests
import logging
from .types import AuthenticatedRequest, Project
from .utils.redis_connection import get_redis

logger = logging.getLogger(__name__)


class ProjectAuthMiddleware:
    """Project-level authentication middleware"""
    
    def __init__(self):
        self.athens_base_url = os.getenv('ATHENS_BASE_URL', 'http://localhost:4000')
        self.signature_secret = os.getenv('SIGNATURE_SHARED_SECRET', '')
        self.cache_expiry_time = int(os.getenv('CACHE_EXPIRY_TIME', '900'))  # 15 minutes default
    
    async def authenticate(self, req: AuthenticatedRequest) -> None:
        """
        Authenticate project using x-app-id, x-app-secret and x-service-id headers
        
        Args:
            req: AuthenticatedRequest object
            
        Raises:
            Exception: If authentication fails
        """
        headers = req.headers
        api_key = headers.get('x-app-id')
        secret = headers.get('x-app-secret')
        service = headers.get('x-service-id')
        
        if not api_key or not secret or not service:
            logger.warning(f"Missing headers - x-app-id: {bool(api_key)}, x-app-secret: {bool(secret)}, x-service-id: {bool(service)}")
            logger.warning(f"Available headers: {list(headers.keys())}")
            raise Exception("Missing API key (x-app-id) or secret (x-app-secret) or (x-service-id) in headers")
        
        try:
            # Check cache first
            redis = await get_redis()
            cache_key = f"project:{api_key}:{secret}:{service}"
            project_data = await redis.get(cache_key)
            
            if not project_data:
                logger.info("Cache miss - verifying with Athens")
                verified_data = await self._verify_with_athens(api_key, secret, service)
                
                # Cache for configured time
                await redis.set(
                    cache_key, 
                    verified_data, 
                    {'EX': self.cache_expiry_time}
                )
                logger.info(f"Cached project data for key: {cache_key}")
                
                req.project = verified_data
            else:
                logger.info("Cache hit - using cached project data")
                req.project = project_data
                
        except Exception as e:
            logger.error(f"Project authentication failed: {str(e)}")
            raise Exception(f"Invalid API credentials: {str(e)}")
    
    async def _verify_with_athens(self, app_id: str, secret: str, service: str) -> Project:
        """
        Verify credentials with Athens service
        
        Args:
            app_id: Application ID
            secret: Application secret
            
        Returns:
            Project information
            
        Raises:
            Exception: If verification fails
        """
        credentials = base64.b64encode(f"{app_id}:{secret}:{service}".encode()).decode()
        
        timestamp = str(int(time.time() * 1000))
        signature_input = f"GET/auth{timestamp}"
        signature = hmac.new(
            self.signature_secret.encode(),
            signature_input.encode(),
            hashlib.sha256
        ).hexdigest()
        
        headers = {
            'Authorization': f'Basic {credentials}',
            'X-Timestamp': timestamp,
            'X-Signature': signature,
        }
        
        try:
            response = requests.get(
                f"{self.athens_base_url}/auth",
                headers=headers,
                timeout=10
            )
            
            if response.status_code != 200:
                logger.error(f"Athens response status: {response.status_code}")
                logger.error(f"Athens response data: {response.text}")
                
                error_message = 'Invalid API credentials'
                
                try:
                    response_data = response.json()
                    if isinstance(response_data, dict):
                        error_message = response_data.get('message') or \
                                      response_data.get('error') or \
                                      f"Athens returned error: {response_data}"
                except:
                    if response.text:
                        error_message = response.text
                
                raise Exception(error_message)
            
            data = response.json()
            
            if not data:
                raise Exception("No data received from Athens")
            
            logger.info("Athens verification passed")
            
            return Project(
                projectUuid=data.get('projectUuid'),
                projectName=data.get('projectName')
            )
            
        except requests.exceptions.ConnectionError:
            raise Exception("Athens service unavailable")
        except requests.exceptions.Timeout:
            raise Exception("Athens service timeout")
        except requests.exceptions.RequestException as e:
            logger.error(f"Athens verification failed: {str(e)}")
            raise Exception(f"Athens verification failed: {str(e)}")