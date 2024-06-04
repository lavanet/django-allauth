from django.urls import path

from . import views

urlpatterns = [
    path(
        "near4/login/",
        views.login_with_wallet,
        name="near_login",
    ),
]
