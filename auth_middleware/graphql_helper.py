# auth_middleware/graphql_helper.py
import os
import functools
from typing import Any, Callable, Optional, Dict
from graphql import GraphQLResolveInfo
from .jwt_guard import JwtAuthMiddleware
from .project_guard import ProjectAuthMiddleware
from .types import GqlContext, AuthenticatedRequest

def _default_service_name() -> str:
    """Read ``SERVICE_NAME`` lazily so dotenv / test setup can take effect."""
    return os.getenv('SERVICE_NAME', 'default')


class GraphQLAuthHelper:
    """GraphQL authentication helper for resolvers"""

    def __init__(self, service_name: Optional[str] = None):
        self.project_auth = ProjectAuthMiddleware(service_name or _default_service_name())
        self.jwt_auth = JwtAuthMiddleware()
    
    async def authorize(
        self,
        resolve: Callable,
        root: Dict[str, Any],
        args: Dict[str, Any],
        context: GqlContext,
        info: GraphQLResolveInfo
    ):
        """
        Direct authorization method for GraphQL resolvers
        
        Args:
            resolve: Resolver function
            root: Root value
            args: Arguments
            context: GraphQL context
            info: GraphQL resolve info
            
        Returns:
            Resolver result
            
        Raises:
            Exception: If authentication fails
        """
        if not context.req:
            raise Exception('Request context not available')
        
        auth_header = context.req.headers.get('authorization')
        if not auth_header:
            raise Exception('Authorization header not found')
        
        try:
            await self.jwt_auth.authenticate(context.req)
            return await resolve(root, args, context, info)
        except Exception as e:
            raise Exception(f'Unauthenticated - Token is invalid: {str(e)}')
    
    async def authenticate_project(self, context: GqlContext) -> None:
        """
        Authenticate project from GraphQL context
        
        Args:
            context: GraphQL context
            
        Raises:
            Exception: If authentication fails
        """
        if not context.req:
            raise Exception('Request context not available')
        await self.project_auth.authenticate(context.req)
    
    async def authenticate_jwt(self, context: GqlContext) -> None:
        """
        Authenticate JWT from GraphQL context
        
        Args:
            context: GraphQL context
            
        Raises:
            Exception: If authentication fails
        """
        if not context.req:
            raise Exception('Request context not available')
        await self.jwt_auth.authenticate(context.req)
    
    def with_project_auth(self, resolver: Callable) -> Callable:
        """
        Decorator for GraphQL resolvers requiring project authentication
        
        Usage:
            @graphql_auth.with_project_auth
            async def resolve_data(root, info, **kwargs):
                project = info.context.req.project
                return {'project': project}
        """
        @functools.wraps(resolver)
        async def wrapper(root: Any, info: GraphQLResolveInfo, **kwargs):
            context = info.context
            await self.authenticate_project(context)
            return await resolver(root, info, **kwargs)
        return wrapper
    
    def with_jwt_auth(self, resolver: Callable) -> Callable:
        """
        Decorator for GraphQL resolvers requiring JWT authentication
        
        Usage:
            @graphql_auth.with_jwt_auth
            async def resolve_user_data(root, info, **kwargs):
                user = info.context.req.user
                return {'user': user}
        """
        @functools.wraps(resolver)
        async def wrapper(root: Any, info: GraphQLResolveInfo, **kwargs):
            context = info.context
            await self.authenticate_jwt(context)
            return await resolver(root, info, **kwargs)
        return wrapper
    
    def with_combined_auth(self, resolver: Callable) -> Callable:
        """
        Decorator for GraphQL resolvers requiring both authentications
        
        Usage:
            @graphql_auth.with_combined_auth
            async def resolve_secure_data(root, info, **kwargs):
                user = info.context.req.user
                project = info.context.req.project
                return {'user': user, 'project': project}
        """
        @functools.wraps(resolver)
        async def wrapper(root: Any, info: GraphQLResolveInfo, **kwargs):
            context = info.context
            await self.authenticate_project(context)
            await self.authenticate_jwt(context)
            return await resolver(root, info, **kwargs)
        return wrapper


# Convenience decorators for direct use
graphql_auth_helper = GraphQLAuthHelper()

project_auth_required = graphql_auth_helper.with_project_auth
jwt_auth_required = graphql_auth_helper.with_jwt_auth
combined_auth_required = graphql_auth_helper.with_combined_auth