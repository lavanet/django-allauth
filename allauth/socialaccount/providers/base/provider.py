import sys,os,logging,random,string,subprocess,uuid
from django.http import JsonResponse
from cryptography.fernet import Fernet
from typing import NamedTuple
from django.http import HttpRequest
from allauth.socialaccount import app_settings
from allauth.socialaccount.adapter import get_adapter
from django.core.exceptions import ImproperlyConfigured
from eth_account.messages import encode_defunct
from web3 import Web3

logger = logging.getLogger(__name__)

def is_uuid(uuid_to_test, version=4):
    try:
        uuid.UUID(uuid_to_test, version=version)
    except ValueError:
        return False
    return True

ALLAUTH_VERBOSE_DEBUG = os.getenv("ALLAUTH_VERBOSE_DEBUG", "False") == "True"

def provider_base_debug_print(format_string, *values):
    if ALLAUTH_VERBOSE_DEBUG:
        print("base/provider.py", format_string.format(*values))

is_empty_string = lambda x: str(x).strip().lower() in ["none", "", "0", "false", "true"]

# Hardcoded private key
key = b'Pzz0Gr4VUhuaVzFmwvEK2WPEgxqoLr7N__MN1aWMenQ='  # This should be 32 url-safe base64-encoded bytes
cipher_suite = Fernet(key)
class UserServerHashType(NamedTuple):
    provider: str
    user_hash: str

class UserServerHashEncoder:
    @staticmethod
    def hash(obj: UserServerHashType) -> str:
        # Concatenate the provider and uid, and convert to bytes
        combined = f"{obj['provider']}:{obj['user_hash']}".encode()

        # Encrypt the combined string using the private key
        encrypted = cipher_suite.encrypt(combined)

        # Return the encrypted string as a base64 string
        return encrypted.decode()

    @staticmethod
    def unhash(encrypted: str) -> UserServerHashType | None:
        try:
            # Convert the base64 string back to bytes
            encrypted = encrypted.encode()

            # Decrypt the combined string using the private key
            combined = cipher_suite.decrypt(encrypted)

            # Split the combined string back into provider and uid
            provider, user_hash = combined.decode().split(":", 1)

            # Return the provider and uid as a UserServerHashType
            return UserServerHashType(provider=provider, user_hash=user_hash)
        except Exception as e:
            provider_base_debug_print(f"Error in unhash: {e}")
            return None

def decode_user_server_hash(request: HttpRequest) -> UserServerHashType | None:
    try:
        # Get the user_server_hash cookie from the request
        user_server_hash = request.COOKIES.get('user_server_hash')

        if user_server_hash is None or str(user_server_hash).strip() in ["None", "", "0"]:
            return None

        return UserServerHashEncoder.unhash(user_server_hash)
    except Exception as e:
        provider_base_debug_print(f"Error in decode_user_server_hash: {e}")
        return None
class ProviderException(Exception):
    pass

class Provider(object):
    slug = None
    uses_apps = True

    def __init__(self, request, app=None):
        self.request = request
        if self.uses_apps and app is None:
            raise ValueError("missing: app")
        self.app = app

    def __str__(self):
        return self.name

    @classmethod
    def get_slug(cls):
        return cls.slug or cls.id

    def get_login_url(self, request, next=None, **kwargs):
        """
        Builds the URL to redirect to when initiating a login for this
        provider.
        """
        raise NotImplementedError("get_login_url() for " + self.name)

    def media_js(self, request):
        """
        Some providers may require extra scripts (e.g. a Facebook connect)
        """
        return ""

    def wrap_account(self, social_account):
        return self.account_class(social_account)

    def get_settings(self):
        return app_settings.PROVIDERS.get(self.id, {})

    def sociallogin_from_response(self, request, response):
        from allauth.socialaccount.adapter import get_adapter
        adapter = get_adapter()

        uid = self.extract_uid(response)
        if not isinstance(uid, str):
            raise ValueError(f"uid must be a string: {repr(uid)}")
        if len(uid) > app_settings.UID_MAX_LENGTH:
            raise ImproperlyConfigured(
                f"SOCIALACCOUNT_UID_MAX_LENGTH too small (<{len(uid)})"
            )
        if not uid:
            raise ValueError("uid must be a non-empty string")
    
        provider_name = self.app.provider_id or self.app.provider

        if provider_name == "google":
            return self.sociallogin_from_response_google(provider_name, adapter, uid, request, response)
        elif provider_name == "twitter":
            return self.sociallogin_from_response_twitter(provider_name, adapter, uid, request, response)
        
        raise Exception("DjangoAllAuth/providers/base.py - sociallogin_from_response add provider to switch case")
        
    def sociallogin_from_response_google(self, provider_name, adapter, uid, request, response):
        from allauth.socialaccount.models import SocialAccount, SocialLogin
        from django.contrib.auth.models import User
        from users.models import UserProfile

        try:
            provider_base_debug_print("sociallogin_from_response_google:: Arguments - provider_name: {}, adapter: {}, uid: {}, request: {}, response: {}", provider_name, adapter, uid, request, response)

            extra_data = self.extract_extra_data(response)
            provider_base_debug_print("sociallogin_from_response_google:: Extra data: {}", extra_data)

            common_fields = self.extract_common_fields(response)
            provider_base_debug_print("sociallogin_from_response_google:: Common fields: {}", common_fields)

            if SocialAccount.objects.filter(uid=uid).exclude(provider=provider_name).exists():
                return JsonResponse({"error": "Uid already exists in the database", "success": False}, status=200)

            socialaccount = SocialAccount.objects.filter(uid=uid, provider=provider_name).first()
            provider_base_debug_print("sociallogin_from_response_google:: Social account: {}", socialaccount)

            if is_empty_string(uid):
                return JsonResponse({"error": "Invliad uid: " + str(uid), "success": False}, status=200)
            
            email = common_fields.get("email")
            if is_empty_string(email):
                return JsonResponse({"error": "Invliad email: " + str(email), "success": False}, status=200)
            
            provider_base_debug_print("sociallogin_from_response_google:: Email: {}", email)

            entry_by_uid = User.objects.filter(username=uid).first()
            provider_base_debug_print("sociallogin_from_response_google:: Entry by uid: {}", entry_by_uid)

            entry_by_email = User.objects.filter(username=email).first()
            provider_base_debug_print("sociallogin_from_response_google:: Entry by email: {}", entry_by_email)

            if entry_by_uid and entry_by_email:
                return JsonResponse({"error": "Database conflict with google login - can not login", "success": False}, status=200)

            user_created = False
            login_user = None
            if not entry_by_uid and not entry_by_email:
                user_created = True
                login_user = User.objects.create(username=uid)
                provider_base_debug_print("sociallogin_from_response_google:: User created: {}", login_user)
            else:
                login_user = entry_by_uid or entry_by_email
                provider_base_debug_print("sociallogin_from_response_google:: Login user: {}", login_user)

            if not socialaccount and not user_created and login_user.id != socialaccount.user_id:
                return JsonResponse({"error": "Uid mismatch for social login", "success": False}, status=200)

            provider_base_debug_print("sociallogin_from_response_google:: Social account created", login_user)

            if user_created:
                login_user.set_password(str(uuid.uuid4()))
                login_user.set_unusable_password()
                provider_base_debug_print("sociallogin_from_response_google:: new user created: ", login_user)

            elif not login_user.is_active:
                provider_base_debug_print("sociallogin_from_response_google:: Your account has been banned")
                return JsonResponse({"error": "Your account has been banned", "success": False},status=200)

            if not socialaccount:
                socialaccount = SocialAccount.objects.create(user=login_user, uid=uid, provider=provider_name)
                provider_base_debug_print("sociallogin_from_response_google:: New social account: {}", socialaccount)

            login_user.profile, profile_created = UserProfile.objects.get_or_create(user=login_user, defaults={'uid': str(uuid.uuid4())})

            if profile_created or is_empty_string(login_user.profile.avatar) or is_empty_string(login_user.profile.nickname):
                login_user.profile.avatar = SocialAccount(extra_data=extra_data, uid=uid, provider=provider_name).get_avatar_url()
                
                if not UserProfile.objects.filter(nickname=email).exists():
                    login_user.profile.nickname = email
                
                login_user.profile.save()

                provider_base_debug_print("sociallogin_from_response_google:: Profile created: {}", login_user.profile)

            provider_base_debug_print("sociallogin_from_response_google:: Social account created", socialaccount)

            sociallogin = SocialLogin(user=login_user, account=socialaccount)
            provider_base_debug_print("sociallogin_from_response_google:: Social login: {}", sociallogin)

            sociallogin.state = SocialLogin.state_from_request(request)
            provider_base_debug_print("sociallogin_from_response_google:: Social login state: {}", sociallogin.state)

            if user_created:
                adapter.populate_user(request, sociallogin, common_fields)
                login_user.save()
                socialaccount.save()
                provider_base_debug_print("sociallogin_from_response_google:: User and social account saved")

            from allauth.socialaccount.helpers import record_authentication, _login_social_account
            record_authentication(request, sociallogin)
            _login_social_account(request, sociallogin)
            provider_base_debug_print("sociallogin_from_response_google:: Authentication recorded and social account logged in")

            return sociallogin

        except Exception as e:
            print(str(e), file=sys.stderr)
            return JsonResponse({"error": "An error occurred during login", "success": False}, status=200)
        
    def sociallogin_from_response_twitter(self, provider_name, adapter, uid, request, response):
        from allauth.socialaccount.models import SocialAccount, SocialLogin
        from users.models import UserProfile

        try:
            user_server_hash: UserServerHashType | None = decode_user_server_hash(request)
            provider_base_debug_print("sociallogin_from_response_twitter:: user_server_hash: {}", user_server_hash)

            if not user_server_hash:
                return JsonResponse({"error": "Twitter login - invalid user_server_hash in request", "success": False}, status=200)

            existing_user = SocialAccount.objects.filter(uid=user_server_hash.user_hash, provider=user_server_hash.provider).last()
            provider_base_debug_print("sociallogin_from_response_twitter:: existing_user: {}", existing_user)

            if not existing_user:
                return JsonResponse({"error": "Twitter login - Error with twitter login 1", "success": False}, status=200)

            if existing_user.user and not existing_user.user.is_active:
                provider_base_debug_print("sociallogin_from_response_google:: Your account has been banned")
                return JsonResponse({"error": "Your account has been banned", "success": False}, status=200)
        
            common_fields = self.extract_common_fields(response)
            name_parts = (common_fields.get("name") or "").partition(" ")
            provider_base_debug_print("sociallogin_from_response_twitter:: name_parts: {}, common_fields:{}", name_parts, common_fields)

            twitter_id = common_fields.get("username")
            if is_empty_string(twitter_id):
                return JsonResponse({"error": "twitter id can not be empty", "success": False}, status=200)
            
            twitter_email = common_fields.get("email")

            profile, profile_created = UserProfile.objects.get_or_create(user=existing_user.user, defaults={'uid': str(uuid.uuid4())})

            twitter_id_exists = not is_empty_string(profile.twitter_id)
            twitter_id_linked = UserProfile.objects.filter(twitter_id=twitter_id).exists()
            twitter_email_linked = not is_empty_string(twitter_email) and UserProfile.objects.filter(twitter_email=twitter_email).exists()
            twitter_id_matches = twitter_id == profile.twitter_id
            twitter_email_matches = not is_empty_string(twitter_email) and twitter_email == profile.twitter_email

            if not twitter_id_exists and twitter_id_linked:
                return JsonResponse({"error": f"twitter id {twitter_id} already linked in the db", "success": False}, status=200)

            if not twitter_id_exists and twitter_email_linked:
                return JsonResponse({"error": f"twitter email {twitter_email} already linked in the db", "success": False}, status=200)

            if twitter_id_exists and not twitter_id_matches:
                return JsonResponse({"error": f"existing user does not match twitter id: {twitter_id}", "success": False}, status=200)

            if twitter_id_exists and not twitter_email_matches:
                return JsonResponse({"error": f"existing user does not match twitter email: {twitter_email}", "success": False}, status=200)

            if is_empty_string(existing_user.user.first_name) or is_empty_string(existing_user.user.last_name):
                existing_user.user.first_name = name_parts[0]
                existing_user.user.last_name = name_parts[2]
                existing_user.user.save()

            extra_data = self.extract_extra_data(response)
            provider_base_debug_print("sociallogin_from_response_twitter:: User saved. extra_data: {}", extra_data)

            updated = False

            if profile_created or is_empty_string(profile.twitter_id):
                profile.twitter_id = twitter_id
                updated = True

            if profile_created or is_empty_string(profile.twitter_email):
                profile.twitter_email = twitter_email
                updated = True

            if profile_created or is_empty_string(profile.avatar):
                profile.avatar = SocialAccount(extra_data=extra_data, uid=uid, provider="twitter").get_avatar_url()
                updated = True

            if profile_created or is_empty_string(profile.nickname):
                nickname = twitter_id
                if not is_empty_string(common_fields.get("name")):
                    nickname = common_fields.get("name")
                    if not UserProfile.objects.filter(nickname=nickname).exists():
                        profile.nickname = nickname
                        updated = True

            if updated:
                profile.save()

            provider_base_debug_print("sociallogin_from_response_twitter:: twitter_id: {}", twitter_id)
            provider_base_debug_print("sociallogin_from_response_twitter:: twitter_email: {}", twitter_email)
            provider_base_debug_print("sociallogin_from_response_twitter:: avatar: {}", existing_user.user.profile.avatar)

            return SocialLogin(user=existing_user.user, account=existing_user)

        except Exception as e:
            print(str(e), file=sys.stderr)
            return JsonResponse({"error": "An error occurred during Twitter login", "success": False}, status=200)

    def extract_uid(self, data):
        """
        Extracts the unique user ID from `data`
        """
        raise NotImplementedError(
            "The provider must implement the `extract_uid()` method"
        )

    def extract_extra_data(self, data):
        """
        Extracts fields from `data` that will be stored in
        `SocialAccount`'s `extra_data` JSONField.

        :return: any JSON-serializable Python structure.
        """
        return data

    def extract_common_fields(self, data):
        """
        Extracts fields from `data` that will be used to populate the
        `User` model in the `SOCIALACCOUNT_ADAPTER`'s `populate_user()`
        method.

        For example:

            {'first_name': 'John'}

        :return: dictionary of key-value pairs.
        """
        return {}

    def cleanup_email_addresses(self, email, addresses, email_verified=False):
        # Avoid loading models before adapters have been registered.
        from allauth.account.models import EmailAddress

        # Move user.email over to EmailAddress
        if email and email.lower() not in [a.email.lower() for a in addresses]:
            addresses.append(
                EmailAddress(email=email, verified=bool(email_verified), primary=True)
            )
        # Force verified emails
        adapter = get_adapter()
        for address in addresses:
            if adapter.is_email_verified(self, address.email):
                address.verified = True

    def extract_email_addresses(self, data):
        """
        For example:

        [EmailAddress(email='john@example.com',
                      verified=True,
                      primary=True)]
        """
        return []

    @classmethod
    def get_package(cls):
        pkg = getattr(cls, "package", None)
        if not pkg:
            pkg = cls.__module__.rpartition(".")[0]
        return pkg


class ProviderAccount(object):
    def __init__(self, social_account):
        self.account = social_account

    def get_profile_url(self):
        return None

    def get_avatar_url(self):
        return None

    def get_brand(self):
        """
        Returns a dict containing an id and name identifying the
        brand. Useful when displaying logos next to accounts in
        templates.

        For most providers, these are identical to the provider. For
        OpenID however, the brand can derived from the OpenID identity
        url.
        """
        provider = self.account.get_provider()
        return dict(id=provider.id, name=provider.name)

    def __str__(self):
        return self.to_str()

    def to_str(self):
        """
        This did not use to work in the past due to py2 compatibility:

            class GoogleAccount(ProviderAccount):
                def __str__(self):
                    dflt = super(GoogleAccount, self).__str__()
                    return self.account.extra_data.get('name', dflt)

        So we have this method `to_str` that can be overridden in a conventional
        fashion, without having to worry about it.
        """
        return self.get_brand()["name"]


class CryptoWalletAccount(ProviderAccount):
    def to_str(self):
        return self.account.uid


class CryptoWalletProvider(Provider):
    id = ""
    name = ""
    account_class = CryptoWalletAccount

    @property
    def get_app_settings(self) -> dict:
        return app_settings.PROVIDERS.get(self.id, {})

    @staticmethod
    def get_nonce() -> str:
        return "".join(
            random.SystemRandom().choice(string.ascii_uppercase + string.digits)
            for _ in range(32)
        )

    def verify_signature(
        self,
        account: str,
        social_token: str,
        nonce: str,
        provider_id: str,
        public_key: str = None,
    ) -> bool:

        # print("provider_id", provider_id)

        # Continue processing the request
        if provider_id in ["metamask"]: #, "walletconnect"]:
            if account.startswith("0x"):
                # This is an Ethereum-based wallet
                try:
                    w3 = Web3(Web3.HTTPProvider(self.get_app_settings.get("url")))
                    message_hash = encode_defunct(text=social_token)
                    recovered_account_address = w3.eth.account.recover_message(
                        message_hash, signature=nonce
                    )
                    return bool(recovered_account_address.lower() == account.lower())
                except Exception:
                    return False
            return False

        # elif account.startswith("cosmos"):
        # else:
        elif provider_id in ["keplr", "leap"]: 
            if not public_key:
                return False

            try:
                # Path to the binary file
                binary_path = self.get_app_settings.get("signature_verifier_binary")

                # Check if the binary file exists
                if not os.path.isfile(binary_path):
                    logger.error(
                        "Error: Binary file '{}' not found.".format(binary_path)
                    )
                    return False

                # Command to execute
                command = [
                    binary_path,
                    "--nonce",
                    f"{social_token}",
                    "--pubkey_type",
                    "tendermint/PubKeySecp256k1",
                    "--pubkey_value",
                    f"{public_key}",
                    "--signature",
                    f"{nonce}",
                ]

                # Execute the command
                process = subprocess.Popen(
                    command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                stdout, stderr = process.communicate()
                exit_code = process.returncode

                # Output stdout, stderr, and exit code
                std_out_string = stdout.decode()
                std_err_string = stderr.decode()
                concatenated_output = std_out_string + std_err_string
                ret_value = exit_code == 0 and (
                    "Signature valid" in concatenated_output
                )  # 0 exit code is a valid response
                return ret_value

            except Exception as e:
                logger.exception("failed parsing keplr signature", e)
                return False

        # elif provider_id in ["near"]:
        #     provider_debug_print(f"provider.py near:: provider_id: {provider_id}")

        #     if not public_key:
        #         provider_debug_print("provider.py near:: public_key is not provided")
        #         return False

        #     try:
        #         # Path to the binary file
        #         binary_path = self.get_app_settings.get(
        #             "near_signature_verifier_binary"
        #         )
        #         provider_debug_print(f"provider.py near:: binary_path: {binary_path}")

        #         # Check if the binary file exists
        #         if not os.path.isfile(binary_path):
        #             logger.error(
        #                 "Near:: Error: Binary file '{}' not found.".format(binary_path)
        #             )
        #             return False

        #         # Command to execute
        #         command = [
        #             binary_path,
        #             f"--publicKey",
        #             public_key,
        #             f"--signature",
        #             nonce,
        #             f"--message",
        #             social_token,
        #         ]

        #         provider_debug_print(f"provider.py near:: command: {command}")

        #         # Execute the command
        #         process = subprocess.Popen(
        #             command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        #         )
        #         stdout, stderr = process.communicate()
        #         exit_code = process.returncode

        #         # Output stdout, stderr, and exit code
        #         std_out_string = stdout.decode()
        #         provider_debug_print(
        #             f"provider.py near:: std_out_string: {std_out_string}"
        #         )

        #         std_err_string = stderr.decode()
        #         provider_debug_print(
        #             f"provider.py near:: std_err_string: {std_err_string}"
        #         )

        #         concatenated_output = std_out_string + std_err_string
        #         provider_debug_print(
        #             f"provider.py near:: concatenated_output: {concatenated_output}"
        #         )
        #         provider_debug_print(f"provider.py near:: exit_code: {exit_code}")

        #         ret_value = exit_code == 0 and (
        #             "Signature is valid" in concatenated_output
        #         )  # 0 exit code is a valid response
        #         provider_debug_print(f"provider.py:: ret_value: {ret_value}")
        #         return ret_value

        #     except Exception as e:
        #         logger.exception("Near:: failed parsing near signature", e)
        #         return False

        else:
            # Unsupported wallet type
            return False

    def get_login_url(self, request, **kwargs):
        return ""

    def extract_common_fields(self, data) -> dict:
        return dict(
            username=data.get("account"),
        )

    def extract_uid(self, data) -> str:
        if "account" not in data:
            raise ProviderException(f"{self.id} error", data)
        return str(data["account"])

