from django.shortcuts import render, redirect
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.contrib.auth import get_user_model
from django.middleware.csrf import get_token
from django.urls import reverse
from django.utils.http import urlencode

from src.users import services as user_services
from src.core.exceptions import APIError, DomainValidationError
from .forms import ActivationForm, TOTPVerifyForm, LoginForm, EmailOTPVerifyForm

User = get_user_model()


@require_http_methods(["GET", "POST"])
def activate_view(request):
    """
    /ui/activate/?token=...
    Étapes:
      - GET: afficher formulaire (password + enable_totp)
      - POST: activer le compte; si enable_totp, afficher le QR et la vérif TOTP.
    """
    token = request.GET.get("token") or request.POST.get("token")
    if not token:
        messages.error(request, "Lien d’activation invalide.")
        return render(
            request,
            "webui/activate.html",
            {"form": ActivationForm(), "token": "", "csrf": get_token(request)},
        )

    if request.method == "GET":
        return render(
            request,
            "webui/activate.html",
            {"form": ActivationForm(), "token": token, "csrf": get_token(request)},
        )

    form = ActivationForm(request.POST)
    if not form.is_valid():
        return render(
            request,
            "webui/activate.html",
            {"form": form, "token": token, "csrf": get_token(request)},
        )

    try:
        user = user_services.user_activate_account(
            token=token,
            password=form.cleaned_data["password"],
            enable_totp=form.cleaned_data["enable_totp"],
        )
    except DomainValidationError as e:
        messages.error(request, e.message or "Activation impossible.")
        return render(
            request,
            "webui/activate.html",
            {"form": form, "token": token, "csrf": get_token(request)},
        )
    except Exception:
        messages.error(request, "Erreur interne pendant l’activation.")
        return render(
            request,
            "webui/activate.html",
            {"form": form, "token": token, "csrf": get_token(request)},
        )

    # Si TOTP demandé, afficher le QR et permettre la vérification immédiate
    if form.cleaned_data["enable_totp"]:
        request.session["webui_last_activated_user_id"] = str(user.id)
        totp_qr = user_services.user_generate_totp_qr(user=user)
        return render(
            request,
            "webui/totp_setup.html",
            {"totp_qr": totp_qr, "form": TOTPVerifyForm(), "csrf": get_token(request)},
        )

    messages.success(request, "Compte activé. Vous pouvez vous connecter.")
    return redirect(reverse("webui:login"))


@require_http_methods(["POST"])
def _totp_verify_step(request):
    """POST interne depuis la page TOTP (soumis via totp_setup.html)."""
    uid = request.session.get("webui_last_activated_user_id")
    if not uid:
        messages.error(request, "Session expirée. Merci de relancer l’activation.")
        return redirect(reverse("webui:activate"))

    form = TOTPVerifyForm(request.POST)
    totp_qr = None
    try:
        user = User.objects.get(id=uid)
        if "totp_qr" in request.POST:
            totp_qr = request.POST["totp_qr"]
    except User.DoesNotExist:
        messages.error(request, "Utilisateur introuvable.")
        return redirect(reverse("webui:activate"))

    if not form.is_valid():
        return render(
            request,
            "webui/totp_setup.html",
            {"totp_qr": totp_qr, "form": form, "csrf": get_token(request)},
        )

    ok = user_services.user_verify_totp(user=user, code=form.cleaned_data["code"])
    if not ok:
        messages.error(request, "Code TOTP invalide.")
        return render(
            request,
            "webui/totp_setup.html",
            {"totp_qr": totp_qr, "form": form, "csrf": get_token(request)},
        )

    messages.success(request, "TOTP activé. Vous pouvez vous connecter.")
    request.session.pop("webui_last_activated_user_id", None)
    return redirect(reverse("webui:login"))


@require_http_methods(["GET", "POST"])
def login_view(request):
    """
    Petit login de test (session) pour accéder à la page OTP.
    On vérifie email/mot de passe et on met l’ID en session.
    """
    if request.method == "GET":
        return render(
            request,
            "webui/login.html",
            {"form": LoginForm(), "csrf": get_token(request)},
        )

    form = LoginForm(request.POST)
    if not form.is_valid():
        return render(
            request, "webui/login.html", {"form": form, "csrf": get_token(request)}
        )

    try:
        user = User.objects.get(email=form.cleaned_data["email"].strip().lower())
        if not user.check_password(form.cleaned_data["password"]):
            raise User.DoesNotExist
    except User.DoesNotExist:
        messages.error(request, "Identifiants invalides.")
        return render(
            request, "webui/login.html", {"form": form, "csrf": get_token(request)}
        )

    request.session["webui_user_id"] = str(user.id)
    messages.success(request, "Connecté.")
    return redirect(reverse("webui:otp"))


@require_http_methods(["POST"])
def logout_view(request):
    request.session.flush()
    messages.info(request, "Déconnecté.")
    return redirect(reverse("webui:login"))


@require_http_methods(["GET", "POST"])
def otp_view(request):
    """
    Page de test OTP e-mail: bouton pour générer, formulaire pour vérifier.
    """
    uid = request.session.get("webui_user_id")
    user = None
    if uid:
        try:
            user = User.objects.get(id=uid)
        except User.DoesNotExist:
            user = None

    if not user:
        messages.info(request, "Veuillez vous connecter.")
        return redirect(reverse("webui:login"))

    if request.method == "POST":
        # Deux actions possibles: generate ou verify (selon le bouton)
        if "generate" in request.POST:
            try:
                user_services.user_generate_email_otp(user=user)
                messages.success(request, "OTP e-mail envoyé (valide 10 min).")
            except DomainValidationError as e:
                messages.error(request, e.message or "Rate limit.")
        elif "verify" in request.POST:
            form = EmailOTPVerifyForm(request.POST)
            if form.is_valid():
                try:
                    user_services.user_verify_email_otp(
                        user=user, code=form.cleaned_data["code"]
                    )
                    messages.success(request, "OTP vérifié.")
                except DomainValidationError as e:
                    messages.error(request, e.message or "OTP invalide/expiré.")
            else:
                messages.error(request, "Formulaire invalide.")
        return redirect(reverse("webui:otp"))

    return render(
        request,
        "webui/otp.html",
        {"form": EmailOTPVerifyForm(), "user": user, "csrf": get_token(request)},
    )


# Bonus: compat pour les anciens liens /activate?token=...
# Ajoutez dans urls.py principal un mapping vers cette vue utilitaire.
def activation_redirect(request):
    token = request.GET.get("token", "")
    url = reverse("webui:activate")
    q = urlencode({"token": token}) if token else ""
    return redirect(f"{url}?{q}" if q else url)
