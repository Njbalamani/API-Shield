from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm

from .models import User


class LoginForm(AuthenticationForm):
    username = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={"autocomplete": "username", "placeholder": "you@example.com"}),
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )

    def clean_username(self):
        return self.cleaned_data["username"].strip().lower()


class RegistrationForm(UserCreationForm):
    organization_name = forms.CharField(max_length=180, label="Organization name")
    organization_slug = forms.SlugField(max_length=200, required=False, label="Organization URL slug")

    class Meta:
        model = User
        fields = ("username", "email", "full_name")
        field_classes = {"email": forms.EmailField}

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def clean_username(self):
        username = self.cleaned_data["username"].strip()
        if User.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError("This username is already taken.")
        return username


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("username", "email", "full_name")
        field_classes = {"email": forms.EmailField}

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if User.objects.filter(email__iexact=email).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def clean_username(self):
        username = self.cleaned_data["username"].strip()
        if User.objects.filter(username__iexact=username).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError("This username is already taken.")
        return username


class ApiKeyCreateForm(forms.Form):
    name = forms.CharField(max_length=120, label="Key name")

    def clean_name(self):
        return self.cleaned_data["name"].strip()
