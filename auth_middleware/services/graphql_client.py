# auth_middleware/services/graphql_client.py
"""
Lightweight GraphQL client for Mercury mutations.
Mirrors the Node.js createApolloClient utility.

The underlying HTTP library (``requests``) is synchronous; ``mutate_async``
offloads each request to a worker thread with ``asyncio.to_thread`` so it
does not block the event loop when called from async code.
"""
import asyncio
import logging
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

# GraphQL mutation strings (mirrors Node queries.ts)
GENERATE_SERVICE_TOKEN = """
mutation GenerateServiceToken($input: ServiceTokenInput) {
    generateServiceToken(input: $input) {
        access_token
        scope
        token_type
        expires_in
    }
}
"""

GET_REGISTERED_SERVICE_BY_CLIENT_ID = """
mutation GetRegisteredServiceByClientId($input: GetRegisteredServiceByClientIdInput) {
    getRegisteredServiceByClientId(input: $input) {
        uuid
    }
}
"""


def create_graphql_client(uri: str, headers: Optional[Dict[str, str]] = None):
    """
    Create a simple GraphQL client (callable object) that executes queries
    against the given URI.

    Args:
        uri: GraphQL endpoint URL
        headers: Optional extra headers

    Returns:
        A GraphQLClient instance
    """
    return GraphQLClient(uri, headers)


class GraphQLClient:
    """Minimal GraphQL client wrapping requests."""

    def __init__(self, uri: str, headers: Optional[Dict[str, str]] = None):
        self.uri = uri
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            **(headers or {}),
        }

    def mutate(
        self,
        mutation: str,
        variables: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a GraphQL mutation synchronously.

        Prefer ``mutate_async`` from async code paths so the event loop does
        not block on the network round-trip.

        Args:
            mutation: GraphQL mutation string
            variables: Variables for the mutation

        Returns:
            The ``data`` portion of the GraphQL response (an empty dict if absent).

        Raises:
            Exception: On network or GraphQL errors.
        """
        payload: Dict[str, Any] = {'query': mutation}
        if variables is not None:
            payload['variables'] = variables

        try:
            response = requests.post(
                self.uri,
                json=payload,
                headers=self.headers,
                timeout=10,
            )

            if response.status_code != 200:
                raise Exception(
                    f"GraphQL request failed with status {response.status_code}: {response.text}"
                )

            result = response.json()

            if 'errors' in result and result['errors']:
                error_messages = '; '.join(
                    e.get('message', str(e)) for e in result['errors']
                )
                raise Exception(f"GraphQL errors: {error_messages}")

            return result.get('data', {})

        except requests.exceptions.ConnectionError:
            raise Exception('Mercury service unavailable')
        except requests.exceptions.Timeout:
            raise Exception('Mercury service timeout')
        except requests.exceptions.RequestException as e:
            raise Exception(f"GraphQL request failed: {str(e)}")

    async def mutate_async(
        self,
        mutation: str,
        variables: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Async wrapper that runs ``mutate`` in a worker thread."""
        return await asyncio.to_thread(self.mutate, mutation, variables)
