from allauth.socialaccount.providers.keplr.provider import LeapProvider
from allauth.tests import TestCase, patch


class LeapTests(TestCase):
    provider_id = LeapProvider.id
