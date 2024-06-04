from django.urls import path

from . import views

urlpatterns = [
    path(
        "keplr4/login/",
        views.login_with_wallet,
        name="keplr_login",
    ),
]
