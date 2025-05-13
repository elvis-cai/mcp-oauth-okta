import os
import secrets
import time
import logging
from typing import Any

from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException

from mcp.server.fastmcp.server import FastMCP
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import (
    OAuthAuthorizationServerProvider,
    OAuthClientInformationFull,
    AuthorizationParams,
    AuthorizationCode,
    AccessToken,
    RefreshToken,
    OAuthToken,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.shared._httpx_utils import create_mcp_http_client

logger = logging.getLogger(__name__)


class ServerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MCP_OKTA_")

    host: str = "localhost"
    port: int = 8000
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:8000")

    okta_client_id: str
    okta_client_secret: str
    okta_issuer: str
    okta_callback_path: str = "http://localhost:8000/okta/callback"

    mcp_scope: str = "user"
    okta_scope: str = "okta.users.read"


class SimpleOktaOAuthProvider(OAuthAuthorizationServerProvider):
    def __init__(self, settings: ServerSettings):
        self.settings = settings
        self.clients = {}
        self.auth_codes = {}
        self.tokens = {}
        self.state_mapping = {}
        # Store Okta tokens with MCP tokens using the format:
        # {"mcp_token": "okta_token"}
        self.token_mapping = {}


    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        state = params.state or secrets.token_hex(16)
        logging.info(params)
        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "client_id": client.client_id,
            "code_challenge": params.code_challenge,
        }
        logging.info(self.settings)
        return (
            f"{self.settings.okta_issuer}/v1/authorize"
            f"?client_id={self.settings.okta_client_id}"
            f"&response_type=code"
            f"&scope={self.settings.okta_scope}"
            f"&redirect_uri={self.settings.okta_callback_path}"
            f"&state={state}"
        )

    async def handle_okta_callback(self, code: str, state: str) -> str:
        state_data = self.state_mapping.get(state)
        if not state_data:
            raise HTTPException(400, "Invalid state parameter")

        redirect_uri = state_data["redirect_uri"]
        client_id = state_data["client_id"]
        client_code_challenge = state_data.get("code_challenge")


        async with create_mcp_http_client() as client:
            response = await client.post(
                f"{self.settings.okta_issuer}/v1/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.settings.okta_callback_path,
                    "client_id": self.settings.okta_client_id,
                    "client_secret": self.settings.okta_client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            data = response.json()
            access_token = data.get("access_token")
            
            okta_token = access_token
            if not access_token:
                raise ValueError(f"❌ Token exchange failed: {data}")  # This gives full reason from Okta

            new_code = f"mcp_{secrets.token_hex(16)}"
            self.auth_codes[new_code] = AuthorizationCode(
                code=new_code,
                client_id=client_id,
                redirect_uri=AnyHttpUrl(redirect_uri),
                redirect_uri_provided_explicitly=True,
                expires_at=time.time() + 300,
                scopes=[self.settings.mcp_scope],
                code_challenge=client_code_challenge,
            )

            self.tokens[okta_token] = AccessToken(
                token=okta_token,
                client_id=client_id,
                scopes=[self.settings.okta_scope],
                expires_at = int(time.time()) + 3600 
            )

        del self.state_mapping[state]
        return construct_redirect_uri(redirect_uri, code=new_code, state=state)

    async def load_authorization_code(self, client: OAuthClientInformationFull, code: str) -> AuthorizationCode | None:
        return self.auth_codes.get(code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        if authorization_code.code not in self.auth_codes:
            raise ValueError("Invalid authorization code")

        mcp_token = f"mcp_{secrets.token_hex(32)}"

        self.tokens[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at = int(time.time()) + 3600 
        )

        # Find GitHub token for this client
        okta_token = next(
            (
                token
                for token, data in self.tokens.items()
                if data.client_id == client.client_id
            ),
            None,
        )
        
        self.token_mapping[mcp_token] = okta_token
        del self.auth_codes[authorization_code.code]

        return OAuthToken(
            access_token=mcp_token,
            token_type="bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        access_token = self.tokens.get(token)
        if not access_token:
            return None
        if access_token.expires_at and access_token.expires_at < time.time():
            del self.tokens[token]
            return None
        return access_token

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        return None

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        raise NotImplementedError("Not supported")

    async def revoke_token(self, token: str, token_type_hint: str | None = None):
        if token in self.tokens:
            del self.tokens[token]


def create_simple_mcp_server(settings: ServerSettings) -> FastMCP:
    oauth_provider = SimpleOktaOAuthProvider(settings)

    auth_settings = AuthSettings(
        issuer_url=settings.server_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=[settings.mcp_scope],
            default_scopes=[settings.mcp_scope],
        ),
        required_scopes=[settings.mcp_scope],
    )

    app = FastMCP(
        name="Simple Okta MCP Server",
        instructions="A simple MCP server with Okta SSO authentication",
        auth_server_provider=oauth_provider,
        host=settings.host,
        port=settings.port,
        debug=True,
        auth=auth_settings,
    )

    @app.custom_route("/okta/callback", methods=["GET"])
    async def okta_callback_handler(request: Request) -> Response:
        code = request.query_params.get("code")
        state = request.query_params.get("state")

        if not code or not state:
            raise HTTPException(400, "Missing code or state parameter")

        try:
            redirect_uri = await oauth_provider.handle_okta_callback(code, state)
            return RedirectResponse(status_code=302, url=redirect_uri)
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Unexpected error", exc_info=e)
            return JSONResponse(
                status_code=500,
                content={"error": "server_error", "error_description": "Unexpected error"},
            )

    def get_okta_token() -> str:
        """Get the Okta token for the authenticated user."""
        access_token = get_access_token()
        if not access_token:
            raise ValueError("Not authenticated")

        # Get GitHub token from mapping
        okta_token = oauth_provider.token_mapping.get(access_token.token)

        if not okta_token:
            raise ValueError("No GitHub token found for user")

        return okta_token

    @app.tool()
    async def list_users() -> dict[str, Any]:
        okta_token = get_okta_token()
        async with create_mcp_http_client() as client:
            response = await client.get(
                
                f"{settings.okta_issuer.replace('/oauth2', '')}/api/v1/users",
                headers={"Authorization": f"Bearer {okta_token}"},
            )
            if response.status_code != 200:
                raise ValueError(f"Okta API error: {response.status_code} - {response.text}")
            return response.json()

    @app.tool()
    async def add(a: int, b: int) -> int:
        return a + b

    @app.resource("greeting://{name}")
    async def get_greeting(name: str) -> str:
        return f"Hello, {name}!"

    return app


logging.basicConfig(level=logging.INFO)
try:
    settings = ServerSettings()
except ValueError as e:
    logger.error("Failed to load settings. Check your env vars.")
    raise

mcp = create_simple_mcp_server(settings)
mcp.run(transport="sse")
