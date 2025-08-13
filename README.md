# Auth Middleware Python Package

A comprehensive authentication middleware package for Python web applications supporting JWT and Project-based authentication.

## Features

- **Dual Authentication Methods**: JWT tokens for users, API keys for projects
- **Framework Support**: Flask, FastAPI, and GraphQL
- **JWKS Support**: Dynamic key rotation with RS512 algorithm
- **Redis Caching**: Performance optimization with configurable TTL
- **Token Revocation**: Check for revoked tokens via Redis
- **Multi-tenant**: Support for project-specific JWT signing keys
- **Type Safety**: Full type hints for better IDE support

## Installation

```bash
pip install auth-middleware
```

Or add to your `requirements.txt`:

```
auth-middleware>=1.0.0
```

## Configuration

Set the following environment variables:

```bash
# Required
REDIS_URL=redis://localhost:6379/0
ATHENS_BASE_URL=http://localhost:4000  # Project auth service
MERCURY_BASE_URL=http://localhost:4000  # JWT issuer
SIGNATURE_SHARED_SECRET=your-shared-secret

# Optional
ATHENS_PROJECT_UUID=default-project-uuid
CACHE_EXPIRY_TIME=900  # Project cache TTL in seconds (default: 15 min)
```

## Usage Examples

### Flask Integration

```python
from flask import Flask, jsonify, g
from auth_middleware import flask_jwt_auth, flask_project_auth, flask_combined_auth

app = Flask(__name__)

# JWT Authentication
@app.route('/api/user/profile')
@flask_jwt_auth()
def get_user_profile():
    user = g.user
    return jsonify({
        'uuid': user['uuid'],
        'email': user['email'],
        'name': user['name']
    })

# Project Authentication
@app.route('/api/project/data')
@flask_project_auth()
def get_project_data():
    project = g.project
    return jsonify({
        'projectUuid': project['projectUuid'],
        'projectName': project['projectName']
    })

# Combined Authentication (both required)
@app.route('/api/secure/resource')
@flask_combined_auth()
def get_secure_resource():
    user = g.user
    project = g.project
    return jsonify({
        'user': user,
        'project': project,
        'data': 'sensitive information'
    })

if __name__ == '__main__':
    app.run(debug=True)
```

### FastAPI Integration

```python
from fastapi import FastAPI, Depends
from auth_middleware import (
    fastapi_jwt_auth,
    fastapi_project_auth,
    fastapi_combined_auth
)

app = FastAPI()

# JWT Authentication
@app.get('/api/user/profile')
async def get_user_profile(user = Depends(fastapi_jwt_auth)):
    return {
        'uuid': user['uuid'],
        'email': user['email'],
        'name': user['name']
    }

# Project Authentication
@app.get('/api/project/data')
async def get_project_data(project = Depends(fastapi_project_auth)):
    return {
        'projectUuid': project['projectUuid'],
        'projectName': project['projectName']
    }

# Combined Authentication
@app.get('/api/secure/resource')
async def get_secure_resource(auth_data = Depends(fastapi_combined_auth)):
    return {
        'user': auth_data['user'],
        'project': auth_data['project'],
        'data': 'sensitive information'
    }
```

### GraphQL Integration (with Graphene)

```python
import graphene
from auth_middleware import (
    GraphQLAuthHelper,
    jwt_auth_required,
    project_auth_required,
    combined_auth_required,
    GqlContext,
    AuthenticatedRequest
)

# Initialize helper
graphql_auth = GraphQLAuthHelper()

class UserType(graphene.ObjectType):
    uuid = graphene.String()
    email = graphene.String()
    name = graphene.String()

class Query(graphene.ObjectType):
    # JWT protected query
    @jwt_auth_required
    async def resolve_current_user(self, info):
        user = info.context.req.user
        return UserType(
            uuid=user['uuid'],
            email=user['email'],
            name=user['name']
        )
    
    # Project protected query
    @project_auth_required
    async def resolve_project_info(self, info):
        project = info.context.req.project
        return {
            'projectUuid': project['projectUuid'],
            'projectName': project['projectName']
        }
    
    # Both authentications required
    @combined_auth_required
    async def resolve_secure_data(self, info):
        user = info.context.req.user
        project = info.context.req.project
        return {
            'user': user,
            'project': project,
            'sensitive_data': 'classified information'
        }

# Setup GraphQL with Flask
from flask import Flask
from flask_graphql import GraphQLView

app = Flask(__name__)

def get_context():
    # Create context with authenticated request
    return GqlContext(AuthenticatedRequest(request))

app.add_url_rule(
    '/graphql',
    view_func=GraphQLView.as_view(
        'graphql',
        schema=graphene.Schema(query=Query),
        graphiql=True,
        get_context=get_context
    )
)
```

### Direct Middleware Usage

```python
import asyncio
from auth_middleware import JwtAuthMiddleware, ProjectAuthMiddleware, AuthenticatedRequest

async def authenticate_request(request):
    # JWT Authentication
    jwt_auth = JwtAuthMiddleware()
    auth_req = AuthenticatedRequest(request)
    
    try:
        await jwt_auth.authenticate(auth_req)
        print(f"Authenticated user: {auth_req.user}")
    except Exception as e:
        print(f"JWT auth failed: {e}")
    
    # Project Authentication
    project_auth = ProjectAuthMiddleware()
    
    try:
        await project_auth.authenticate(auth_req)
        print(f"Authenticated project: {auth_req.project}")
    except Exception as e:
        print(f"Project auth failed: {e}")

# Run authentication
# asyncio.run(authenticate_request(your_request_object))
```

## API Headers

### JWT Authentication
```http
Authorization: Bearer <jwt_token>
```

### Project Authentication
```http
x-app-id: <application_id>
x-app-secret: <application_secret>
```

## Token Structure

The JWT tokens should have the following structure:

```json
{
  "sub": {
    "uuid": "user-uuid",
    "email": "user@example.com",
    "name": "User Name"
  },
  "project_uuid": "project-uuid",
  "type": "access",
  "iss": "http://mercury.example.com",
  "aud": "http://athens.example.com",
  "exp": 1234567890,
  "nbf": 1234567890,
  "iat": 1234567890,
  "jti": "token-id"
}
```

## Error Handling

The middleware raises exceptions with descriptive messages:

```python
from flask import Flask, jsonify
from auth_middleware import flask_jwt_auth

app = Flask(__name__)

@app.route('/api/protected')
@flask_jwt_auth()
def protected_route():
    # This is only reached if authentication succeeds
    return jsonify({'message': 'Success'})

@app.errorhandler(401)
def handle_auth_error(e):
    return jsonify({'error': str(e)}), 401
```

## Caching Strategy

- **Project credentials**: Cached for 15 minutes (configurable via `CACHE_EXPIRY_TIME`)
- **JWT tokens**: Cached for 1 hour after validation
- **JWKS keys**: Cached for 10 minutes
- **Revoked tokens**: Checked on every request

## Development

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# With coverage
pytest --cov=auth_middleware
```

### Code Quality

```bash
# Format code
black auth_middleware/

# Lint
flake8 auth_middleware/

# Type checking
mypy auth_middleware/
```

## Architecture

The package mirrors the TypeScript implementation with Python-specific adaptations:

- **Async/await support** for all authentication methods
- **Framework-specific adapters** for Flask (sync) and FastAPI (async)
- **Type hints** throughout for better IDE support
- **Singleton Redis connection** manager for efficiency
- **Decorator pattern** for clean integration

## License

MIT

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Support

For issues and questions, please use the GitHub issue tracker.