from typing import Dict, Optional, Any, TypedDict
from dataclasses import dataclass
from datetime import datetime


class AuthUser(TypedDict):
    """Authenticated user information"""
    uuid: str
    email: str
    name: str


class Project(TypedDict):
    """Project information"""
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
    """Complete JWT Payload structure"""
    sub: Optional[JwtPayloadSub]
    project_uuid: Optional[str]
    type: str
    iss: str  # issuer - mercury.{domain}.com
    aud: str  # audience - athens.{domain}.com
    exp: int  # expiration timestamp
    nbf: int  # not before timestamp
    iat: int  # issued at timestamp
    jti: Optional[str] = None  # JWT ID for revocation tracking


class AuthenticatedRequest:
    """Extended request object with authentication data"""
    def __init__(self, request: Any):
        self.request = request
        self.project: Optional[Project] = None
        self.user: Optional[AuthUser] = None
        
    @property
    def headers(self) -> Dict[str, str]:
        """Get headers from the underlying request object"""
        # Handle different frameworks (Flask, FastAPI, etc.)
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