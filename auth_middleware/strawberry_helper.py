# auth_middleware/strawberry_helper.py
"""
Strawberry GraphQL authentication helpers
"""
import os
import functools
from typing import Any, Awaitable, Callable, Optional, TypeVar, Union
from strawberry.types import Info
from strawberry.permission import BasePermission
from strawberry.extensions import Extension
from .jwt_guard import JwtAuthMiddleware
from .project_guard import ProjectAuthMiddleware
from .types import AuthenticatedRequest, AuthUser, ProjectContext
from graphql import GraphQLError
import logging
import inspect

logger = logging.getLogger(__name__)

T = TypeVar("T")

def _default_service_name() -> str:
    """
    Read ``SERVICE_NAME`` lazily so test setups and late ``dotenv`` loads
    are honoured. If unset, fall back to ``'default'`` — which is a footgun
    in production (any service-aware logic will silently misbehave); set
    ``SERVICE_NAME`` explicitly in deployment.
    """
    return os.getenv('SERVICE_NAME', 'default')


class JWTAuthPermission(BasePermission):
    """
    Strawberry permission class for JWT authentication
    
    Usage:
        @strawberry.field(permission_classes=[JWTAuthPermission])
        def secure_field(self) -> str:
            return "Secure data"
    """
    message = "User is not authenticated"
    
    async def has_permission(
        self, 
        source: Any, 
        info: Info, 
        **kwargs
    ) -> bool:
        """Check if request has valid JWT token"""
        try:
            # Get request from context
            request = info.context.get("request")
            if not request:
                return False
            
            # Create authenticated request wrapper
            auth_req = AuthenticatedRequest(request)
            
            # Authenticate with JWT
            jwt_auth = JwtAuthMiddleware()
            await jwt_auth.authenticate(auth_req)
            
            # Store user in context for later use
            info.context["user"] = auth_req.user
            
            return True
        except Exception as e:
            logger.error(f"JWT authentication failed: {e}")
            return False

class ProjectAuthPermission(BasePermission):
    message = "Project is not authenticated"

    async def has_permission(self, source: Any, info: Info, **kwargs) -> bool:
        try:
            request = info.context.get("request")
            if not request:
                raise GraphQLError("Request not found in context")

            auth_req = AuthenticatedRequest(request)
            # Surface a clean error for the missing-header case, before the
            # middleware wraps it in the noisy "Authentication service error".
            if not auth_req.headers.get('x-project-token'):
                raise GraphQLError("Unauthorized: missing 'x-project-token' header")

            project_auth = ProjectAuthMiddleware(_default_service_name())
            await project_auth.authenticate(auth_req)

            info.context["project"] = auth_req.project
            info.context["platform"] = auth_req.platform
            info.context["service_ctx"] = auth_req.service
            return True

        except GraphQLError as gql_err:
            raise gql_err
        except Exception as e:
            logger.error(f"Project authentication failed: {e}")
            raise GraphQLError(f"Unauthorized: {e}")

class CombinedAuthPermission(BasePermission):
    """
    Strawberry permission class for both JWT and Project authentication
    
    Usage:
        @strawberry.field(permission_classes=[CombinedAuthPermission])
        def highly_secure_field(self) -> str:
            return "Very secure data"
    """
    message = "Both user and project authentication required"
    
    async def has_permission(
        self, 
        source: Any, 
        info: Info, 
        **kwargs
    ) -> bool:
        """Check if request has both valid JWT and project credentials"""
        try:
            # Get request from context
            request = info.context.get("request")
            if not request:
                return False
            
            # Create authenticated request wrapper
            auth_req = AuthenticatedRequest(request)
            
            # Authenticate both
            jwt_auth = JwtAuthMiddleware()
            project_auth = ProjectAuthMiddleware(_default_service_name())
            
            await jwt_auth.authenticate(auth_req)
            await project_auth.authenticate(auth_req)
            
            # Store both in context
            info.context["user"] = auth_req.user
            info.context["project"] = auth_req.project
            
            return True
        except Exception as e:
            logger.error(f"Combined authentication failed: {e}")
            return False

class AuthenticationExtension(Extension):
    """
    Strawberry extension for authentication
    Adds authentication info to the execution context
    """
    
    async def on_request_start(self):
        """Called at the start of request"""
        request = self.execution_context.context.get("request")
        if request:
            # Initialize auth request wrapper
            auth_req = AuthenticatedRequest(request)
            self.execution_context.context["auth_request"] = auth_req
    
    async def on_request_end(self):
        """Called at the end of request"""
        pass

# Decorator-based authentication for Strawberry resolvers
def requires_jwt_auth(func):
    """Decorator for JWT authentication on resolver functions 
    Usage:
        @strawberry.field
        @requires_jwt_auth
        async def secure_field(self, info: Info) -> str:
            user = info.context["user"]
            return f"Hello {user['name']}"
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        # Find `info` from args or kwargs
        info = next((a for a in args if isinstance(a, Info)), None)
        if info is None:
            info = kwargs.get("info")
        if info is None:
            raise Exception("Could not find GraphQL Info object")

        request = info.context.get("request")
        if not request:
            raise Exception("No request found in context")
        
        # Run JWT auth
        auth_req = AuthenticatedRequest(request)
        jwt_auth = JwtAuthMiddleware()
        await jwt_auth.authenticate(auth_req)
        info.context["user"] = auth_req.user

        return await func(*args, **kwargs)
    return wrapper

def requires_project_auth(func):
    """
    Decorator for Project authentication on resolver functions
    
    Usage:
        @strawberry.field
        @requires_project_auth
        async def get_project_data(self, info: Info) -> str:
            project = info.context["project"]
            return f"Project: {project['projectName']}"
    """
    @functools.wraps(func)
    async def wrapper(*args, info: Info, **kwargs):
        request = getattr(info.context, "request", None) or info.context.get("request")
        if not request:
            raise GraphQLError("Request not found in context")

        # Authenticate
        auth_req = AuthenticatedRequest(request)
        project_auth = ProjectAuthMiddleware(_default_service_name())
        try:
            await project_auth.authenticate(auth_req)
        except Exception as e:
            raise GraphQLError(f"Unauthorized: {e}")

        # Store project on context
        if isinstance(info.context, dict):
            info.context["project"] = auth_req.project
        else:
            setattr(info.context, "project", auth_req.project)

        return await func(*args, info=info, **kwargs)
    return wrapper

def requires_combined_auth(func: Callable) -> Callable:
    """
    Decorator for combined authentication on resolver functions.

    Usage:
        @strawberry.field
        @requires_combined_auth
        async def get_secure_data(self, info: Info) -> str:
            user = info.context["user"]
            project = info.context["project"]
            return f"User {user['name']} in project {project['projectName']}"
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        # Find the Info object in args or kwargs
        info = next((a for a in args if isinstance(a, Info)), kwargs.get("info"))
        if not info:
            raise Exception("Info object not found in resolver arguments")

        # Get request from context
        request = info.context.get("request")
        if not request:
            raise Exception("Request not found in context")

        # Authenticate
        auth_req = AuthenticatedRequest(request)
        jwt_auth = JwtAuthMiddleware()
        project_auth = ProjectAuthMiddleware(_default_service_name())

        await jwt_auth.authenticate(auth_req)
        await project_auth.authenticate(auth_req)

        # Store both in context
        info.context["user"] = auth_req.user
        info.context["project"] = auth_req.project

        # Call resolver appropriately
        if inspect.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            return func(*args, **kwargs)

    return wrapper

# Helper functions to get auth data from context
def get_current_user(info: Info) -> Optional[AuthUser]:
    """Get current authenticated user from context"""
    return info.context.get("user")

def get_current_project(info: Info) -> Optional[ProjectContext]:
    """Get current authenticated project from context"""
    return info.context.get("project")

def is_authenticated(info: Info) -> bool:
    """Check if user is authenticated"""
    return "user" in info.context

def is_project_authenticated(info: Info) -> bool:
    """Check if project is authenticated"""
    return "project" in info.context