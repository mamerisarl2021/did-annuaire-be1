from django import forms


class ActivationForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput, label="Mot de passe")
    confirm_password = forms.CharField(
        widget=forms.PasswordInput, label="Confirmer le mot de passe"
    )
    enable_totp = forms.BooleanField(
        required=False, label="Activer l’authentification via application (TOTP)"
    )

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("password") != cleaned.get("confirm_password"):
            self.add_error(
                "confirm_password", "Les mots de passe ne correspondent pas."
            )
        return cleaned


class TOTPVerifyForm(forms.Form):
    code = forms.CharField(label="Code TOTP (6 chiffres)", max_length=6)


class LoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)


class EmailOTPVerifyForm(forms.Form):
    code = forms.CharField(label="Code OTP (6 chiffres)", max_length=6)
