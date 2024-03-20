from allauth.socialaccount.providers.base.views import WalletLoginView

from .provider import NearProvider


class NearLoginView(WalletLoginView):
    provider_id = NearProvider.id


login_with_wallet = NearLoginView.as_view()
