"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import os
import json
from typing import Dict, Any
import requests
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.base_client import OAuthError
from authlib.common.security import generate_token
from protocol_interfaces import OAuth2ProtocolInterface
from logutils import get_logger

logger = get_logger(__name__)

DEFAULT_CONFIG = {
    "urls": {
        "auth_uri": "https://slack.com/oauth/v2/authorize",
        "token_uri": "https://slack.com/api/oauth.v2.access",
        "userinfo_uri": "https://slack.com/api/users.profile.get",
        "send_message_uri": "https://slack.com/api/chat.postMessage",
        "revoke_uri": "https://slack.com/api/auth.revoke",
        "users_list_uri": "https://slack.com/api/users.list",
    },
    "params": {
        "scope": [
            "chat:write",
            "users.profile:read",
            "users:read",
            "users:read.email",
        ]
    },
}


def load_credentials(configs: Dict[str, Any]) -> Dict[str, str]:
    """Load OAuth2 credentials from a specified configuration."""

    creds_config = configs.get("credentials", {})
    creds_path = os.path.expanduser(creds_config.get("path", ""))
    if not creds_path:
        raise ValueError("Missing 'credentials.path' in configuration.")
    if not os.path.isabs(creds_path):
        creds_path = os.path.join(os.path.dirname(__file__), creds_path)

    logger.debug("Loading credentials from %s", creds_path)
    with open(creds_path, encoding="utf-8") as f:
        creds = json.load(f)

    return {
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
        "redirect_uri": creds["redirect_uris"][0],
    }


class SlackOAuth2Adapter(OAuth2ProtocolInterface):
    """Adapter for integrating Slack's OAuth2 protocol."""

    def __init__(self):
        self.default_config = DEFAULT_CONFIG
        self.credentials = load_credentials(self.config)
        self.session = OAuth2Session(
            client_id=self.credentials["client_id"],
            client_secret=self.credentials["client_secret"],
            redirect_uri=self.credentials["redirect_uri"],
            token_endpoint=self.default_config["urls"]["token_uri"],
        )

    def get_authorization_url(self, **kwargs):
        code_verifier = kwargs.get("code_verifier")
        autogenerate_code_verifier = kwargs.pop("autogenerate_code_verifier", False)
        redirect_url = kwargs.pop("redirect_url", None)

        if autogenerate_code_verifier and not code_verifier:
            code_verifier = generate_token(48)
            kwargs["code_verifier"] = code_verifier
            self.session.code_challenge_method = "S256"

        if code_verifier:
            kwargs["code_verifier"] = code_verifier
            self.session.code_challenge_method = "S256"

        if redirect_url:
            self.session.redirect_uri = redirect_url

        params = {**self.default_config["params"], **kwargs}

        authorization_url, state = self.session.create_authorization_url(
            self.default_config["urls"]["auth_uri"], **params
        )

        slack_authorization_url = authorization_url.replace("scope=", "user_scope=")
        logger.debug("Authorization URL generated: %s", slack_authorization_url)

        return {
            "authorization_url": slack_authorization_url,
            "state": state,
            "code_verifier": code_verifier,
            "client_id": self.credentials["client_id"],
            "scope": ",".join(self.default_config["params"]["scope"]),
            "redirect_uri": self.session.redirect_uri,
        }

    def exchange_code_and_fetch_user_info(self, code, **kwargs):
        redirect_url = kwargs.pop("redirect_url", None)

        if redirect_url:
            self.session.redirect_uri = redirect_url

        try:
            token_response = self.session.fetch_token(
                self.default_config["urls"]["token_uri"], code=code, **kwargs
            )
            if not token_response.get("ok"):
                raise ValueError(
                    "Failed to fetch access token: " + token_response.get("error", "")
                )

            users_token = token_response["authed_user"]
            self.session.token = users_token
            logger.info("Access token fetched successfully.")

            if not users_token.get("refresh_token"):
                raise ValueError("No refresh token found in the response.")

            fetched_scopes = set(users_token.get("scope", "").split(","))
            expected_scopes = set(self.default_config["params"]["scope"])

            if not expected_scopes.issubset(fetched_scopes):
                raise ValueError(
                    f"Invalid token: Scopes do not match. Expected: {expected_scopes}, "
                    f"Received: {fetched_scopes}"
                )

            headers = {
                "Authorization": f"Bearer {users_token['access_token']}",
                "Content-Type": "application/json",
            }

            userinfo_response = requests.get(
                self.default_config["urls"]["userinfo_uri"], headers=headers, timeout=10
            ).json()
            if not userinfo_response.get("ok"):
                raise ValueError(
                    "Failed to fetch user info: " + userinfo_response.get("error", "")
                )
            users_profile = userinfo_response["profile"]
            user_label = users_profile.get("email") or users_profile.get("real_name")

            account_identifier = (
                f"{token_response["team"]["id"]}[{token_response["team"]["name"]}]--"
                f"{users_token["id"]}[{user_label}]"
            )
            userinfo = {
                "account_identifier": account_identifier,
                "name": users_profile.get("real_name"),
            }
            logger.info("User information fetched successfully.")

            return {"token": users_token, "userinfo": userinfo}
        except OAuthError as e:
            logger.error("Failed to fetch token or user info: %s", e)
            raise

    def revoke_token(self, token, **kwargs):
        self.session.token = token
        try:
            refreshed_tokens = self.session.refresh_token(
                self.default_config["urls"]["token_uri"]
            )
            self.session.token = refreshed_tokens
            response = self.session.revoke_token(
                self.default_config["urls"]["revoke_uri"],
                token_type_hint="refresh_token",
            )

            if not response.ok:
                raise RuntimeError(response.text)

            response_data = response.json()
            if not response_data.get("ok"):
                raise RuntimeError(response_data)
            response.raise_for_status()

            logger.info("Token revoked successfully.")
            return True
        except OAuthError as e:
            logger.error("Failed to revoke tokens: %s", e)
            raise

    def _resolve_user_id(self, access_token, username_or_email):
        """
        Helper method to resolve user ID from username or email.

        Args:
            access_token (str): The access token for API calls
            username_or_email (str): Username or email to resolve (without @ prefix)

        Returns:
            str: User ID if found, None otherwise
        """
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }

            response = requests.get(
                self.default_config["urls"]["users_list_uri"],
                headers=headers,
                timeout=10,
            )

            if not response.ok:
                logger.error("Failed to fetch users list: %s", response.text)
                return None

            response_data = response.json()
            if not response_data.get("ok"):
                logger.error("Failed to fetch users list: %s", response_data)
                return None

            users = response_data.get("members", [])

            for user in users:
                if user.get("deleted") or user.get("is_bot"):
                    continue

                if user.get("name") == username_or_email:
                    return user.get("id")

                profile = user.get("profile", {})
                if profile.get("real_name") == username_or_email:
                    return user.get("id")

                if profile.get("email") == username_or_email:
                    return user.get("id")

                if profile.get("display_name") == username_or_email:
                    return user.get("id")

            logger.warning("User not found: %s", username_or_email)
            return None

        except (requests.RequestException, KeyError, ValueError) as e:
            logger.error("Error resolving user ID for %s: %s", username_or_email, e)
            return None

    def send_message(self, token, message, **kwargs):
        recipient = kwargs.get("recipient")
        if not recipient:
            raise ValueError("Recipient channel or user ID must be provided.")

        self.session.token = token

        try:
            refreshed_tokens = self.session.refresh_token(
                self.default_config["urls"]["token_uri"]
            )
            access_token = refreshed_tokens.get("access_token")

            if not access_token:
                logger.error("Token refresh did not return an access token.")
                raise RuntimeError("Missing access token after refresh.")

            if recipient.startswith("@"):
                username_or_email = recipient[1:]
                resolved_user_id = self._resolve_user_id(
                    access_token, username_or_email
                )
                if resolved_user_id:
                    recipient = resolved_user_id
                    logger.info(
                        "Resolved @%s to user ID: %s",
                        username_or_email,
                        resolved_user_id,
                    )
                else:
                    logger.warning(
                        "Could not resolve @%s to user ID, using original recipient",
                        username_or_email,
                    )

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }

            response = requests.post(
                self.default_config["urls"]["send_message_uri"],
                headers=headers,
                json={"channel": recipient, "text": message},
                timeout=10,
            )

            if not response.ok:
                raise RuntimeError(response.text)

            response_data = response.json()
            if not response_data.get("ok"):
                raise RuntimeError(response_data)
            response.raise_for_status()

            logger.info("Successfully sent message.")
            return {"success": True, "refreshed_token": refreshed_tokens}

        except OAuthError as e:
            logger.exception("Failed to send message: %s", e)
            raise
