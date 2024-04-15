from django.urls import path

from . import views

urlpatterns = [
    path(
        "metamask1/login/",
        views.login_with_wallet,
        name="metamask_login",
    ),
]
