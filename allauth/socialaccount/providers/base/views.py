import json
import logging

from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.helpers import (
    complete_social_login,
)
from allauth.socialaccount.models import SocialLogin, SocialToken, SocialAccount
from allauth.socialaccount.providers.base.forms import WalletLoginForm
from datetime import timedelta
from django import forms
from django.apps import apps
from django.conf import settings
from django.contrib.auth import logout, get_user_model
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse, HttpRequest
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt


logger = logging.getLogger(__name__)


Invite = apps.get_model("invites", "Invite")

import os  
ALLAUTH_VERBOSE_DEBUG = os.getenv('ALLAUTH_VERBOSE_DEBUG', 'False') == 'True'
def views_debug_print(*args):
    if ALLAUTH_VERBOSE_DEBUG:
        print(*args)
    
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

    def login(self, request: HttpRequest, data: dict[str, str]) -> JsonResponse:
        """
        Process wallet login based on the provided data.
        """

        try:
            process = data["process"]
            account = data["account"]
            public_key = data["public_key"]
            invite_code = data["invite_code"]
            base_login_token = data.get("base_login_token", "")

            views_debug_print(f"djang-allauth login. Process: {process}")
            views_debug_print(f"djang-allauth login. Account: {account}")
            views_debug_print(f"djang-allauth login. Public Key: {public_key}")
            views_debug_print(f"djang-allauth login. Invite Code: {invite_code}")
            views_debug_print(f"djang-allauth login. Base Login Token: {base_login_token}")

            # Store user ID and process type in request
            request.uid = account
            request.process = process

            views_debug_print(f"djang-allauth login. Request UID: {request.uid}")
            views_debug_print(f"djang-allauth login. Request Process: {request.process}")

            # Handle login token if present
            if "login_token" in data:
                request.session["login_token"] = data["login_token"]

            views_debug_print(f"djang-allauth login. Login Token: {request.session.get('login_token')}")

            cache_key = f"allauth.wallet.{account}"

            views_debug_print(f"djang-allauth login. Cache Key: {cache_key} ")
            
            nonce = self.provider.get_nonce()

            views_debug_print(f"djang-allauth login. Nonce: {nonce} ")

            if process == "token":
                request.session["login_token"] = nonce

                # Create a social login object from the response
                login = self.provider.sociallogin_from_response(request, data)
                views_debug_print(f'djang-allauth login. login: {login}')

                if invite_code:
                    if invite := Invite.objects.filter(code=invite_code).last():
                        views_debug_print(f'djang-allauth login. invite: {invite}')
                        if not invite.is_valid():
                            views_debug_print('djang-allauth login. Invalid invitation')
                            return JsonResponse(
                                {"data": "No valid invitation", "success": False},
                                status=401,
                            )
                else:
                    if not SocialAccount.objects.filter(uid=account).exists():
                        views_debug_print('djang-allauth login. Non existing account')
                        return JsonResponse(
                            {"data": "Non existing account", "success": False},
                            status=401,
                        )

                login.state = SocialLogin.state_from_request(request)
                views_debug_print(f'djang-allauth login. login.state: {login.state}')

                cache.set(cache_key, nonce, timeout=600)
                views_debug_print('djang-allauth login. Cache set')

                ret = complete_social_login(request, login)
                views_debug_print(f'djang-allauth login. ret: {ret}')

                # This is two-step login. Unless we verified the user's signature (in the "verify" step)
                # we shouldn't log him in
                logout(request)
                views_debug_print('djang-allauth login. User logged out')

                return JsonResponse({"data": nonce, "success": bool(ret)}, status=200)

            if process == "verify":

                cache_token = cache.get(cache_key)

                if cache_token:
                    views_debug_print('djang-allauth login verify. Token was picked from cache.', cache_token)
                    token = cache_token
                else:
                    views_debug_print('djang-allauth login verify. base_login_token was used.', base_login_token)
                    token = base_login_token

                signature = None

                # Verify the login process using existing tokens
                if token:
                    signature = token
                    if signature:
                        nonce = request.session.get("login_token")
                        if self.provider.verify_signature(
                            account, signature, nonce, self.provider_id, public_key
                        ):
                            request.session["login_token"] = nonce
                            login = self.provider.sociallogin_from_response(
                                request, data
                            )
                            login.state = SocialLogin.state_from_request(request)
                            complete_social_login(request, login)
                            return JsonResponse(
                                {"data": str(login.user.profile.uid), "success": True},
                                status=200,
                            )

                        else:
                            return JsonResponse(
                                {"data": "Wrong signature", "success": False},
                                status=400,
                            )
                    else:
                        return JsonResponse(
                            {"data": "No signature", "success": False}, status=400
                        )
                else:
                    return JsonResponse(
                        {"data": "No existing tokens", "success": False}, status=400
                    )

            return JsonResponse({"data": "Wrong process", "success": False}, status=400)

        except Exception as e:
            logger.exception(e)
            return JsonResponse({}, status=500)
