import json, logging, uuid, os, datetime

from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.providers.base.forms import WalletLoginForm
from django import forms
from django.apps import apps
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse, HttpRequest
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt


logger = logging.getLogger(__name__)

Invite = apps.get_model("invites", "Invite")

ALLAUTH_VERBOSE_DEBUG = os.getenv("ALLAUTH_VERBOSE_DEBUG", "False") == "True"

def views_debug_print(*args):
    if ALLAUTH_VERBOSE_DEBUG:
        print(f"[{datetime.datetime.now()}] base/views.py ::", *args)

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

        # Only preload stuff when the request is POST request (avoid having a heavy OPTIONS request)
        if request.method == "POST":
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
            return JsonResponse({"error": "Invalid JSON"}, status=200)

        return self.login(request, form.cleaned_data)

    def process_token(self, invite_code):
        nonce = self.provider.get_nonce()

        views_debug_print(f"djang-allauth process_token. Nonce: {nonce} ")

        if invite_code:
            if invite := Invite.objects.filter(code=invite_code).last():
                views_debug_print("djang-allauth process_token. invite: ", invite)
                if not invite.is_valid():
                    views_debug_print("djang-allauth login. Invalid invitation")
                    return JsonResponse({"error": "No valid invitation", "success": False},status=200)
                
        return JsonResponse({"data": nonce, "success": True}, status=200)

    def process_verify(self, request, account, data):
        public_key = data["public_key"]
        views_debug_print("djang-allauth process_verify. Public Key: ", public_key)

        nonce_token_from_request = data.get("base_login_token", "")
        views_debug_print(
            f"djang-allauth process_verify. Base Login Token: {nonce_token_from_request}"
        )
    
        if not nonce_token_from_request:
            views_debug_print("djang-allauth process_verify. No existing tokens. Nonce Token from Request: ", nonce_token_from_request)
            return JsonResponse({"error": "No existing tokens", "success": False}, status=200)

        signed_token = data.get("login_token")
        views_debug_print("djang-allauth process_verify. Signed Token: ", signed_token) 

        if not signed_token:
            views_debug_print(
                f"djang-allauth process_verify. No signature. Signed Token: {signed_token}"
            )
            return JsonResponse({"error": "No signature", "success": False}, status=200)

        provider_name = self.provider.app.provider_id or self.provider.app.provider
        if not provider_name in ["metamask", "keplr", "leap", "near", "trustwallet", "walletconnect"]:
            return JsonResponse({"error": "Unsported provider", "success": False}, status=200)
        
        if self.provider.verify_signature(
            account,
            nonce_token_from_request,
            signed_token,
            self.provider_id,
            public_key,
        ):
            views_debug_print(
                "djang-allauth process_verify verify. Token was nonce_token_from_request. Arguments to verify_signature: ",
                " account:", account,
                " nonce_token_from_request:", nonce_token_from_request,
                " signed_token:", signed_token,
                " provider_id:", self.provider_id,
                " public_key:", public_key,
            )
        else:
            views_debug_print(
                "djang-allauth process_verify verify. Failed to verify signature with nonce_token_from_request. Arguments to verify_signature: ",
                " account:", account,
                " nonce_token_from_request:", nonce_token_from_request,
                " signed_token:", signed_token,
                " provider_id:", self.provider_id,
                " public_key:", public_key,
            )
            return JsonResponse({"error": "Wrong signature", "success": False},status=400,)

        views_debug_print("djang-allauth process_verify verify. Verify flow passed")

        from allauth.socialaccount.models import SocialAccount, SocialLogin

        if SocialAccount.objects.exclude(provider=provider_name).filter(uid=account).exists():
            return JsonResponse({"error": "Login invalid - use the same wallet for login", "success": False},status=200)
        
        from django.contrib.auth.models import User
        from users.models import UserProfile

        # Create or get User
        login_user, user_created = User.objects.get_or_create(username=account)

        if user_created:
            login_user.set_password(str(uuid.uuid4()))
            login_user.set_unusable_password()
            login_user.save()
            views_debug_print("New user created: ", login_user)
        elif not login_user.is_active:
            views_debug_print("djang-allauth process_verify verify. Your account has been banned")
            return JsonResponse({"error": "Your account has been banned", "success": False}, status=200)
        
        # Create or get SocialAccount
        socialaccount, _ = SocialAccount.objects.get_or_create(
            user=login_user,
            uid=account,
            provider=provider_name,
        )

        # Create UserProfile if it doesn't exist
        login_user.profile, _ = UserProfile.objects.get_or_create(
            user=login_user,
            defaults={'uid': str(uuid.uuid4())},
        )
                    
        sociallogin = SocialLogin(
            user = login_user, account=socialaccount
        )

        sociallogin.state = SocialLogin.state_from_request(request)

        from allauth.socialaccount.helpers import record_authentication, _login_social_account
        record_authentication(request, sociallogin)
        _login_social_account(request, sociallogin)

        return JsonResponse(
            {"data": str(login_user.profile.uid), "success": True},
            status=200,
        )

    def login(self, request: HttpRequest, data: dict[str, str]) -> JsonResponse:
        """
        Process wallet login based on the provided data.
        """

        try:
            is_empty_string = lambda x: str(x).strip().lower() in ["none", "", "0", "false", "true"]

            process = data.get("process")
            account = data.get("account")
            invite_code = data.get("invite_code")

            if is_empty_string(process):
                return JsonResponse({"error": "Process must not be an empty string", "success": False}, status=200)
            if is_empty_string(account):
                return JsonResponse({"error": "Account must not be an empty string", "success": False}, status=200)
            if is_empty_string(invite_code):
                return JsonResponse({"error": "Invite code must not be an empty string", "success": False}, status=200)

            views_debug_print("djang-allauth login. Process: ", process, "Account: ", account, "Invite Code: ", invite_code)

            # Store user ID and process type in request
            request.uid = account
            request.process = process

            views_debug_print("djang-allauth login. Request UID: ", account, "Request Process: ", process)

            if process == "token":
                response = self.process_token(invite_code)
                return response

            if process == "verify":
                response = self.process_verify(request, account, data)
                return response

            return JsonResponse({"error": "Wrong process", "success": False}, status=200)

        except Exception as e:
            logger.exception(e)
            return JsonResponse({}, status=500)
