# auth_middleware/express_helper.py
import os
import functools
import asyncio
from typing import Callable, Any, Optional
from flask import Request as FlaskRequest, jsonify, g
from fastapi import HTTPException, Request as FastAPIRequest, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from .project_guard import ProjectAuthMiddleware
from .jwt_guard import JwtAuthMiddleware
from .types import AuthenticatedRequest

_DEFAULT_SERVICE_NAME = os.getenv('SERVICE_NAME', 'default')

# Flask Middleware Decorators

def flask_project_auth():
    """
    Flask decorator for project authentication
    
    Usage:
        @app.route('/api/resource')
        @flask_project_auth()
        def my_endpoint():
            project = g.project
            return jsonify(project)
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            auth_middleware = ProjectAuthMiddleware(_DEFAULT_SERVICE_NAME)
            req = AuthenticatedRequest(FlaskRequest)
            
            try:
                # Run async code in sync context
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(auth_middleware.authenticate(req))
                
                # Store in Flask's g object
                g.project = req.project
                
                return f(*args, **kwargs)
            except Exception as e:
                return jsonify({'error': str(e)}), 401
            finally:
                loop.close()
        
        return wrapper
    return decorator


def flask_jwt_auth():
    """
    Flask decorator for JWT authentication
    
    Usage:
        @app.route('/api/resource')
        @flask_jwt_auth()
        def my_endpoint():
            user = g.user
            return jsonify(user)
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            auth_middleware = JwtAuthMiddleware()
            req = AuthenticatedRequest(FlaskRequest)
            
            try:
                # Run async code in sync context
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(auth_middleware.authenticate(req))
                
                # Store in Flask's g object
                g.user = req.user
                
                return f(*args, **kwargs)
            except Exception as e:
                return jsonify({'error': str(e)}), 401
            finally:
                loop.close()
        
        return wrapper
    return decorator


def flask_combined_auth():
    """
    Flask decorator for combined JWT and project authentication
    
    Usage:
        @app.route('/api/resource')
        @flask_combined_auth()
        def my_endpoint():
            user = g.user
            project = g.project
            return jsonify({'user': user, 'project': project})
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            project_auth = ProjectAuthMiddleware(_DEFAULT_SERVICE_NAME)
            jwt_auth = JwtAuthMiddleware()
            req = AuthenticatedRequest(FlaskRequest)
            
            try:
                # Run async code in sync context
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                # Authenticate both
                loop.run_until_complete(project_auth.authenticate(req))
                loop.run_until_complete(jwt_auth.authenticate(req))
                
                # Store in Flask's g object
                g.project = req.project
                g.user = req.user
                
                return f(*args, **kwargs)
            except Exception as e:
                return jsonify({'error': str(e)}), 401
            finally:
                loop.close()
        
        return wrapper
    return decorator


# FastAPI Dependencies

security = HTTPBearer()


async def fastapi_project_auth(request: FastAPIRequest):
    """
    FastAPI dependency for project authentication
    
    Usage:
        @app.get('/api/resource')
        async def my_endpoint(project = Depends(fastapi_project_auth)):
            return project
    """
    auth_middleware = ProjectAuthMiddleware(_DEFAULT_SERVICE_NAME)
    req = AuthenticatedRequest(request)
    
    try:
        await auth_middleware.authenticate(req)
        return req.project
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


async def fastapi_jwt_auth(
    request: FastAPIRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    FastAPI dependency for JWT authentication
    
    Usage:
        @app.get('/api/resource')
        async def my_endpoint(user = Depends(fastapi_jwt_auth)):
            return user
    """
    auth_middleware = JwtAuthMiddleware()
    req = AuthenticatedRequest(request)
    
    try:
        await auth_middleware.authenticate(req)
        return req.user
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


async def fastapi_combined_auth(
    request: FastAPIRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    FastAPI dependency for combined authentication
    
    Usage:
        @app.get('/api/resource')
        async def my_endpoint(auth_data = Depends(fastapi_combined_auth)):
            user = auth_data['user']
            project = auth_data['project']
            return {'user': user, 'project': project}
    """
    project_auth = ProjectAuthMiddleware(_DEFAULT_SERVICE_NAME)
    jwt_auth = JwtAuthMiddleware()
    req = AuthenticatedRequest(request)
    
    try:
        await project_auth.authenticate(req)
        await jwt_auth.authenticate(req)
        
        return {
            'user': req.user,
            'project': req.project
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))