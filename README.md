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

### GraphQL Integration (with Strawberry)
```
import strawberry
from datetime import datetime
from strawberry.types import Info
from auth_middleware import (
    JWTAuthPermission,
    ProjectAuthPermission,
    CombinedAuthPermission,
    requires_jwt_auth,
    requires_project_auth,
    requires_combined_auth,
    get_current_user,
    get_current_project,
)
from typing import List

# Example data models
@strawberry.type
class Message:
    text: str
    timestamp: datetime
    from_user: str

@strawberry.type
class User:
    uuid: str
    email: str
    name: str

@strawberry.type
class Query:
    # Project-protected field using permission_classes
    @strawberry.field(permission_classes=[ProjectAuthPermission])
    def hello(self, info: Info, name: str = "World") -> str:
        project_data = get_current_project(info)
        return f"Hello {name}! This is a public endpoint. {project_data}"
    
    # JWT-protected field using permission_classes
    @strawberry.field(permission_classes=[JWTAuthPermission])
    def whoami(self, info: Info) -> User:
        user_data = get_current_user(info)
        return User(
            uuid=user_data["uuid"],
            email=user_data["email"],
            name=user_data["name"]
        )
    
    # Project-protected field using decorator
    @strawberry.field
    @requires_project_auth
    async def hello_1(self, info: Info, name: str = "World_1") -> str:
        project_data = get_current_project(info)
        return f"Hello {name}! This is a public endpoint. {project_data}"
    
    # JWT-protected field using decorator
    @strawberry.field
    @requires_jwt_auth
    async def my_messages(self, info: Info) -> List[Message]:
        user = get_current_user(info)
        messages = [
            Message(
                text="Welcome to the authenticated area!",
                timestamp=datetime.now(),
                from_user="System"
            ),
            Message(
                text=f"Hello {user['name']}, you are authenticated!",
                timestamp=datetime.now(),
                from_user="System"
            ),
            Message(
                text="Your JWT token is valid",
                timestamp=datetime.now(),
                from_user="Auth Service"
            )
        ]
        return messages

    # Combined auth using decorator
    @strawberry.field
    @requires_combined_auth
    async def hello_2(self, info: Info, name: str = "World_2") -> str:
        user = info.context["user"]
        project = info.context["project"]
        return f"Hello {user['name']}! This is a public endpoint. {project}"
    
    # Combined auth using permission_classes
    @strawberry.field(permission_classes=[CombinedAuthPermission])
    async def hello_3(self, info: Info, name: str = "World_3") -> str:
        user = info.context["user"]
        project = info.context["project"]
        return f"Hello {user['name']}! This is a public endpoint. {project}"

schema = strawberry.Schema(query=Query)```


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

## Migrating from 1.x to 2.0

Version 2.0 introduces three distinct token types — **platform**, **project**, and
**service** — each with its own payload shape and context object. The legacy
`JwtPayload` dataclass is still exported for backward compatibility but emits a
`DeprecationWarning` on construction; new code should use the typed payloads
and contexts from `auth_middleware.types`.

| 1.x                | 2.0 replacement                                                                       |
| ------------------ | ------------------------------------------------------------------------------------- |
| `JwtPayload`       | `PlatformTokenPayload` / `ProjectTokenPayload` / `UserTokenPayload` / `ServiceTokenPayload` |
| `req.project` dict | `ProjectContext` dataclass (also exposes `tenant_id`; `project_uuid` kept as alias)   |
| Generic `Exception` from `authenticate()` | `AuthenticationError` — catch this single type for all auth failures |

`tenant_id` is the canonical identifier going forward. `project_uuid` is
preserved on `PlatformContext` / `ProjectContext` as an alias of `tenant_id`,
but it is **deprecated** — migrate consumers to `tenant_id` before the next
major bump.

### Failure-mode policy

Revocation lookups (Redis) follow a single configurable policy:

- `REVOCATION_FAIL_OPEN=true` — if Redis is unreachable, allow the token
  through (logs a WARNING). Use only when availability matters more than
  revocation enforcement.
- unset / `false` (default) — if Redis is unreachable, reject the token
  (logs an ERROR). This is the secure default.

The same policy applies to platform-token revocation, project-token
revocation, and the project secret-version lookup.

## Service-token operations

Service tokens are **stateless** — they have no Redis revocation entry, so a
leaked service token is valid until its `exp` claim. To bound the blast radius
of a leak:

- **Keep `expires_in` short.** Mercury issues service tokens with a
  configurable lifetime; **≤ 1 hour** is recommended. Configure the local
  cache TTL via `SERVICE_TOKEN_CACHE_TTL` (default `3300` ≈ 55 min) and never
  set it higher than the issued lifetime.
- **Rotate `CLIENT_SECRET` regularly.** Treat it like a database password —
  scheduled rotation (e.g., every 90 days) plus on-demand rotation on
  suspicion of compromise.

### Emergency `CLIENT_SECRET` rotation runbook

If a service's `CLIENT_SECRET` is suspected to be leaked:

1. **Issue a new secret in Mercury** for the affected service. Keep the old
   one active for now so in-flight requests don't fail mid-rotation.
2. **Roll the new secret to all replicas** of the consuming service. Update
   `CLIENT_SECRET` (deployment env / secret manager) and trigger a rolling
   restart so each replica picks up the new value.
3. **Invalidate cached tokens** on each replica. Either restart the process
   (clears the in-process cache) or call `auth_middleware.clear_cache()` to
   wipe both Redis and in-process caches for the service token + UUID.
4. **Revoke the old secret in Mercury** once all replicas have cycled. Any
   service token previously minted with the old secret is still valid until
   its `exp`, but no new ones can be issued.
5. **Wait out the residual window.** Tokens minted with the old secret remain
   valid until their `exp` claim — this is why short `expires_in` matters.
   For a high-severity leak, consider rotating the **JWKS signing key** in
   Mercury as well; that invalidates every outstanding service token
   immediately at the cost of forcing every consumer to refetch JWKS.
6. **Audit logs** for any use of the old secret after step 4. Anything logged
   after rotation indicates a stale replica or external consumer that missed
   the roll.

Platform and project tokens have Redis-backed revocation entries and can be
revoked individually via the standard Mercury revocation flow.

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