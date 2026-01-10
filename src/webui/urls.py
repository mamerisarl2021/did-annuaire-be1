from django.urls import path
from . import views

app_name = "webui"

urlpatterns = [
    path("activate/", views.activate_view, name="activate"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("otp/", views.otp_view, name="otp"),
]
