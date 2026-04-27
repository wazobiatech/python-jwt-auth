from typing import Dict, Optional, Any, List, TypedDict
from dataclasses import dataclass, field
from datetime import datetime


# ==================== TOKEN PAYLOAD TYPES ====================

@dataclass
class PlatformTokenPayload:
    """Platform token payload structure"""
    tenant_id: str
    secret_version: int
    token_id: str
    type: str  # 'platform'
    scopes: List[str]
    iat: int
    nbf: int
    exp: int
    iss: str  # mercury.{domain}.com
    aud: str  # mercury.{domain}.com

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PlatformTokenPayload':
        return cls(
            tenant_id=data.get('tenant_id', ''),
            secret_version=data.get('secret_version', 0),
            token_id=data.get('token_id', ''),
            type=data.get('type', 'platform'),
            scopes=data.get('scopes', []),
            iat=data.get('iat', 0),
            nbf=data.get('nbf', 0),
            exp=data.get('exp', 0),
            iss=data.get('iss', ''),
            aud=data.get('aud', ''),
        )


@dataclass
class ProjectTokenPayload:
    """Project token payload structure"""
    tenant_id: str
    secret_version: int
    enabled_services: List[str]
    token_id: str
    type: str  # 'project'
    scopes: List[str]
    iat: int
    nbf: int
    exp: int
    iss: str  # mercury.{domain}.com
    aud: str  # *.{domain}.com

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProjectTokenPayload':
        return cls(
            tenant_id=data.get('tenant_id', ''),
            secret_version=data.get('secret_version', 0),
            enabled_services=data.get('enabled_services', []),
            token_id=data.get('token_id', ''),
            type=data.get('type', 'project'),
            scopes=data.get('scopes', []),
            iat=data.get('iat', 0),
            nbf=data.get('nbf', 0),
            exp=data.get('exp', 0),
            iss=data.get('iss', ''),
            aud=data.get('aud', ''),
        )


@dataclass
class UserTokenPayload:
    """User JWT token payload structure"""
    user_id: str
    tenant_id: str
    token_id: str
    type: str  # 'user'
    scopes: List[str]
    iat: int
    nbf: int
    exp: int
    iss: str
    aud: str
    jti: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserTokenPayload':
        return cls(
            user_id=data.get('user_id', ''),
            tenant_id=data.get('tenant_id', ''),
            token_id=data.get('token_id', ''),
            type=data.get('type', 'user'),
            scopes=data.get('scopes', []),
            iat=data.get('iat', 0),
            nbf=data.get('nbf', 0),
            exp=data.get('exp', 0),
            iss=data.get('iss', ''),
            aud=data.get('aud', ''),
            jti=data.get('jti'),
        )


@dataclass
class ServiceTokenPayload:
    """Service token payload structure"""
    type: str  # 'service'
    client_id: str
    service_name: str
    scope: str  # space-separated scopes
    jti: str
    iat: int
    nbf: int
    exp: int
    iss: str
    aud: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ServiceTokenPayload':
        return cls(
            type=data.get('type', 'service'),
            client_id=data.get('client_id', ''),
            service_name=data.get('service_name', ''),
            scope=data.get('scope', ''),
            jti=data.get('jti', ''),
            iat=data.get('iat', 0),
            nbf=data.get('nbf', 0),
            exp=data.get('exp', 0),
            iss=data.get('iss', ''),
            aud=data.get('aud', ''),
        )


# ==================== CONTEXT TYPES ====================

@dataclass
class PlatformContext:
    """Platform context injected onto request after platform token auth"""
    tenant_id: str
    project_uuid: str
    scopes: List[str]
    token_id: str
    expires_at: int


@dataclass
class ProjectContext:
    """Project context injected onto request after project token auth"""
    tenant_id: str
    project_uuid: str
    enabled_services: List[str]
    scopes: List[str]
    secret_version: int
    token_id: str
    expires_at: int


@dataclass
class ServiceContext:
    """Service context injected onto request after service token auth"""
    client_id: str
    service_name: str
    scopes: List[str]
    token_id: str
    issued_at: int
    expires_at: int


class AuthUser(TypedDict, total=False):
    """Authenticated user information"""
    uuid: str
    email: str
    name: str
    tenant_id: str
    permissions: List[str]
    token_id: str


# ==================== LEGACY TYPES (backward compat) ====================

class Project(TypedDict, total=False):
    """Legacy project info — prefer ProjectContext for new code"""
    projectUuid: str
    projectName: str


@dataclass
class JwtPayloadSub:
    """JWT Payload Subject"""
    uuid: str
    email: str
    name: str


@dataclass
class JwtPayload:
    """
    Legacy JWT Payload structure.
    @deprecated Use PlatformTokenPayload, ProjectTokenPayload, UserTokenPayload, or ServiceTokenPayload instead
    """
    sub: Optional[JwtPayloadSub] = None
    project_uuid: Optional[str] = None
    tenant_id: Optional[str] = None
    permissions: Optional[List[str]] = None
    scopes: Optional[List[str]] = None
    type: str = ''
    iss: str = ''
    aud: str = ''
    exp: int = 0
    nbf: int = 0
    iat: int = 0
    jti: Optional[str] = None


# ==================== REQUEST TYPES ====================

class AuthenticatedRequest:
    """Extended request object with authentication data"""
    def __init__(self, request: Any):
        self.request = request
        self.platform: Optional[PlatformContext] = None
        self.project: Optional[ProjectContext] = None
        self.service: Optional[ServiceContext] = None
        self.user: Optional[AuthUser] = None

    @property
    def headers(self) -> Dict[str, str]:
        """Get headers from the underlying request object"""
        if hasattr(self.request, 'headers'):
            return dict(self.request.headers)
        elif hasattr(self.request, 'META'):  # Django
            headers = {}
            for key, value in self.request.META.items():
                if key.startswith('HTTP_'):
                    header_name = key[5:].replace('_', '-').lower()
                    headers[header_name] = value
            return headers
        return {}


class GqlContext:
    """GraphQL context with authenticated request"""
    def __init__(self, request: AuthenticatedRequest):
        self.req = request