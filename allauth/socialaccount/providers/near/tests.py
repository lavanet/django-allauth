from allauth.socialaccount.providers.near.provider import NearProvider
from allauth.tests import TestCase, patch


class NearTests(TestCase):
    provider_id = NearProvider.id
