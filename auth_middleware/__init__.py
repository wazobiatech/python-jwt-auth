"""
Authentication Middleware Package

Provides JWT and Project-based authentication for Python web applications.
Supports Flask, FastAPI, and GraphQL.
"""

from .jwt_guard import JwtAuthMiddleware
from .project_guard import ProjectAuthMiddleware
from .graphql_helper import (
    GraphQLAuthHelper,
    project_auth_required,
    jwt_auth_required,
    combined_auth_required
)
from .express_helper import (
    # Flask decorators
    flask_project_auth,
    flask_jwt_auth,
    flask_combined_auth,
    # FastAPI dependencies
    fastapi_project_auth,
    fastapi_jwt_auth,
    fastapi_combined_auth
)
from .strawberry_helper import (
    # Flask decorators
    get_current_project,
    get_current_user,
    is_authenticated,
    is_project_authenticated,
    requires_combined_auth,
    requires_jwt_auth,
    requires_project_auth,
    JWTAuthPermission,
    ProjectAuthPermission,
    CombinedAuthPermission,
    AuthenticationExtension,
)
from .types import (
    AuthUser,
    Project,
    AuthenticatedRequest,
    GqlContext,
    JwtPayload,
    PlatformTokenPayload,
    ProjectTokenPayload,
    UserTokenPayload,
    ServiceTokenPayload,
    PlatformContext,
    ProjectContext,
    ServiceContext,
)
from .services import generate_token, get_service_by_id, clear_cache

__version__ = '2.0.0'

__all__ = [
    # Core middleware
    'JwtAuthMiddleware',
    'ProjectAuthMiddleware',
    
    # GraphQL helpers
    'GraphQLAuthHelper',
    'project_auth_required',
    'jwt_auth_required',
    'combined_auth_required',
    
    # Flask helpers
    'flask_project_auth',
    'flask_jwt_auth',
    'flask_combined_auth',
    
    # FastAPI helpers
    'fastapi_project_auth',
    'fastapi_jwt_auth',
    'fastapi_combined_auth',
    
    # Types — token payloads
    'PlatformTokenPayload',
    'ProjectTokenPayload',
    'UserTokenPayload',
    'ServiceTokenPayload',

    # Types — context
    'PlatformContext',
    'ProjectContext',
    'ServiceContext',
    'AuthUser',
    'Project',
    'AuthenticatedRequest',
    'GqlContext',
    'JwtPayload',

    # Services
    'generate_token',
    'get_service_by_id',
    'clear_cache',

    # Strawberry helpers
    'get_current_user',
    'get_current_project',
    'is_authenticated',
    'is_project_authenticated',
    'requires_combined_auth',
    'requires_jwt_auth',
    'requires_project_auth',
    'JWTAuthPermission',
    'ProjectAuthPermission',
    'CombinedAuthPermission',
    'AuthenticationExtension',
]