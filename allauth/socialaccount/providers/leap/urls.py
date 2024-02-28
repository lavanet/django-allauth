from django.urls import path

from . import views

urlpatterns = [
    path(
        "leap/login/",
        views.login_with_wallet,
        name="leap_login",
    ),
]
