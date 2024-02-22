import random
import string
import subprocess
import os

from uuid import UUID

from allauth.socialaccount import app_settings
from allauth.socialaccount.adapter import get_adapter
from django.core.exceptions import ImproperlyConfigured
from django.contrib.auth import get_user_model
from eth_account.messages import encode_defunct
from web3 import Web3
import logging
logger = logging.getLogger(__name__)
string_to_check = "Signature valid"

def is_uuid(uuid_to_test, version=4):
    try:
        UUID(uuid_to_test, version=version)
    except ValueError:
        return False
    return True


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
        """
        Instantiates and populates a `SocialLogin` model based on the data
        retrieved in `response`. The method does NOT save the model to the
        DB.

        Data for `SocialLogin` will be extracted from `response` with the
        help of the `.extract_uid()`, `.extract_extra_data()`,
        `.extract_common_fields()`, and `.extract_email_addresses()`
        methods.

        :param request: a Django `HttpRequest` object.
        :param response: object retrieved via the callback response of the
            social auth provider.
        :return: A populated instance of the `SocialLogin` model (unsaved).
        """
        # NOTE: Avoid loading models at top due to registry boot...
        from allauth.socialaccount.adapter import get_adapter
        from allauth.socialaccount.models import SocialAccount, SocialLogin

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

        extra_data = self.extract_extra_data(response)
        common_fields = self.extract_common_fields(response)
        socialaccount = SocialAccount(
            extra_data=extra_data,
            uid=uid,
            provider=(self.app.provider_id or self.app.provider)
            if self.app
            else self.id,
        )
        email_addresses = self.extract_email_addresses(response)
        self.cleanup_email_addresses(
            common_fields.get("email"),
            email_addresses,
            email_verified=common_fields.get("email_verified"),
        )
        sociallogin = SocialLogin(
            account=socialaccount, email_addresses=email_addresses
        )

        try:
            # Adding hacky support for points project
            user_hash = response.get("user_hash", "")
            if is_uuid(user_hash):
                existing_user = (
                    get_user_model().objects.filter(profile__uid=user_hash).last()
                )
                if existing_user:
                    name_parts = (common_fields.get("name") or "").partition(" ")
                    existing_user.firt_name = name_parts[0]
                    existing_user.last_name = name_parts[2]
                    existing_user.save()
                    existing_user.profile.twitter_id = common_fields.get("username")
                    existing_user.profile.twitter_email = common_fields.get("email")
                    existing_user.profile.avatar = socialaccount.get_avatar_url()
                    existing_user.profile.save()

        except Exception as e:
            print(e)

        user = sociallogin.user = adapter.new_user(request, sociallogin)
        user.set_unusable_password()
        adapter.populate_user(request, sociallogin, common_fields)

        return sociallogin

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
        self, account: str, social_token: str, nonce: str, provider_id: str, public_key: str = None
    ) -> bool:
        # Continue processing the request
        if provider_id in ["metamask", "walletconnect"]:
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
        elif provider_id == "keplr":
            if not public_key:
                return False

            try:
                # Path to the binary file
                binary_path = self.get_app_settings.get("signature_verifier_binary")

                # Check if the binary file exists
                if not os.path.isfile(binary_path):
                    logger.error("Error: Binary file '{}' not found.".format(binary_path))
                    return False

                # Command to execute
                command = [binary_path,
                        '--nonce', f'{social_token}',
                        '--pubkey_type', 'tendermint/PubKeySecp256k1',
                        '--pubkey_value', f'{public_key}',
                        '--signature', f'{nonce}']

                # Execute the command
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                exit_code = process.returncode

                # Output stdout, stderr, and exit code
                std_out_string = stdout.decode()
                std_err_string = stderr.decode()
                concatenated_output = std_out_string + std_err_string
                ret_value = exit_code == 0 and (string_to_check in concatenated_output) # 0 exit code is a valid response
                return ret_value

            except Exception as e:
                logger.exception("failed parsing keplr signature", e)
                return False
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
