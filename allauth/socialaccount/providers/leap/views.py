from allauth.socialaccount.providers.base.views import WalletLoginView

from .provider import LeapProvider


class LeapLoginView(WalletLoginView):
    provider_id = LeapProvider.id


login_with_wallet = LeapLoginView.as_view()
