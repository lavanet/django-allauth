import json

from datetime import timedelta, timezone

from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.helpers import (
    complete_social_login,
    render_authentication_error,
)
from allauth.socialaccount.models import SocialLogin, SocialToken
from allauth.socialaccount.providers.base.forms import WalletLoginForm

from django import forms
from django.conf import settings
from django.contrib.auth import logout
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse, HttpRequest
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt


class WalletLoginView(View):
    """
    View for handling wallet-based login for social accounts.
    """

    provider_id = None  # should be set to a specific provider class

    @method_decorator(csrf_exempt)
    def dispatch(self, request: HttpRequest):
        """
        Override dispatch method to set up necessary variables before processing the request.
        """
        # Get adapter instance for social account handling
        self.adapter = get_adapter(request)

        # Retrieve the application configuration for the given provider
        self.app = self.adapter.get_app(request, provider=self.provider_id)

        # Get the provider instance
        self.provider = self.app.get_provider(request)

        try:
            return super().dispatch(request)
        except (forms.ValidationError, PermissionDenied):
            return JsonResponse({}, status=400)

    def post(self, request: HttpRequest) -> JsonResponse:
        """
        Handles POST requests for wallet login.
        """
        try:
            form = WalletLoginForm(json.loads(request.body))

            if not form.is_valid():
                all_errors = {}
                for key, value in form.errors.items():
                    all_errors[key] = value
                return JsonResponse(all_errors, status=400)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        return self.login(request, form.cleaned_data)

    @classmethod
    def _get_existing_tokens(cls, account: str) -> "QuerySet[SocialToken]":
        """
        Retrieve existing tokens for a given account.
        """
        return SocialToken.objects.filter(
            account__uid=account, account__provider=cls.provider_id
        )

    def login(self, request: HttpRequest, data: dict[str, str]) -> JsonResponse:
        """
        Process wallet login based on the provided data.
        """
        try:
            process = data["process"]
            account = data["account"]

            # Store user ID and process type in request
            request.uid = account
            request.process = process

            # Handle login token if present
            if "login_token" in data:
                request.session["login_token"] = data["login_token"]

            nonce = self.provider.get_nonce()

            if process == "token":
                request.session["login_token"] = nonce
                expires_at = timezone.now() + timedelta(
                    seconds=settings.SOCIALACCOUNT_TOKEN_EXPIRATION * 60 * 60
                )

                # Remove any existing tokens associated with this account
                self._get_existing_tokens(account).delete()

                # Create a social login object from the response
                login = self.provider.sociallogin_from_response(request, data)
                login.state = SocialLogin.state_from_request(request)

                # Set up the token with nonce and expiration
                login.token = SocialToken(
                    app=self.app, token=nonce, expires_at=expires_at
                )
                ret = complete_social_login(request, login)

                # This is two-step login. Unless we verified the user's signature (in the "verify" step)
                # we shouldn't log him in
                logout(request)

                return JsonResponse({"data": nonce, "success": bool(ret)}, status=200)

            if process == "verify":
                # Verify the login process using existing tokens
                if social_token := self._get_existing_tokens(account).last():
                    nonce = request.session.get("login_token")
                    if self.provider.verify_signature(
                        account, social_token.token, nonce
                    ):
                        request.session["login_token"] = nonce
                        login = self.provider.sociallogin_from_response(request, data)
                        login.state = SocialLogin.state_from_request(request)
                        complete_social_login(request, login)
                        return JsonResponse({"data": None, "success": True}, status=200)

            return JsonResponse({"data": None, "success": False}, status=400)

        except Exception as e:
            return JsonResponse({}, status=500)