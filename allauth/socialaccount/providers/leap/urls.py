from django.urls import path

from . import views

urlpatterns = [
    path(
        "leap4/login/",
        views.login_with_wallet,
        name="leap_login",
    ),
]
