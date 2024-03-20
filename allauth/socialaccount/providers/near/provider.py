from allauth.socialaccount.providers.base import CryptoWalletProvider


class NearProvider(CryptoWalletProvider):
    id = "near"
    name = "Near"


provider_classes = [NearProvider]
