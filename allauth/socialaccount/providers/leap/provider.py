from allauth.socialaccount.providers.base import CryptoWalletProvider


class LeapProvider(CryptoWalletProvider):
    id = "leap"
    name = "Leap"


provider_classes = [LeapProvider]
