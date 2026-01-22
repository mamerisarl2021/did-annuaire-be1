from django.contrib import admin
from src.users.models import User

# Register your models here.
admin.site.register(User)

# src/users/admin.py
# from django.contrib import admin
# from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
# from .models import User


# @admin.register(User)
# class UserAdmin(BaseUserAdmin):
#    ordering = ("email",)
#    list_display = ("email", "first_name", "last_name", "role", "status", "is_staff", "is_superuser")
#    search_fields = ("email", "first_name", "last_name")

#    fieldsets = (
#        (None, {"fields": ("email", "password")}),
#        ("Personal info", {"fields": ("first_name", "last_name", "phone")}),
#        ("Organization", {"fields": ("organization",)}),
#        ("Permissions",
#         {"fields": ("role", "status", "is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
#        ("2FA", {"fields": ("totp_enabled", "totp_secret")}),
#        ("Important dates", {"fields": ("last_login", "last_login_at", "created_at", "updated_at")}),
#    )

#    add_fieldsets = (
#        (None, {
#            "classes": ("wide",),
#            "fields": ("email", "first_name", "last_name", "password1", "password2", "is_staff", "is_superuser"),
#        }),
#    )

#    readonly_fields = ("created_at", "updated_at")
