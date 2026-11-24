from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django.views.generic import FormView, TemplateView, UpdateView

from accounts.permissions import OrganizationRoleRequiredMixin

from . import services
from .forms import ApiKeyCreateForm, LoginForm, ProfileForm, RegistrationForm
from .models import ApiKey


class AccountLoginView(FormView):
    template_name = "accounts/login.html"
    form_class = LoginForm

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect(self.get_redirect_url())
        return super().dispatch(request, *args, **kwargs)

    def get_redirect_url(self):
        candidate = self.request.POST.get("next") or self.request.GET.get("next")
        if candidate and url_has_allowed_host_and_scheme(
            candidate,
            allowed_hosts={self.request.get_host()},
            require_https=self.request.is_secure(),
        ):
            return candidate
        return settings.LOGIN_REDIRECT_URL

    def form_valid(self, form):
        email = form.cleaned_data["username"]
        user, reason = services.login_user(
            request=self.request,
            email=email,
            password=form.cleaned_data["password"],
        )
        if user is None:
            if reason == "locked":
                form.add_error(None, "Too many failed attempts. Please try again in 15 minutes.")
            else:
                remaining = services.remaining_login_attempts(email, services.client_ip(self.request))
                message = "Invalid email or password."
                if remaining:
                    message = f"{message} {remaining} attempt(s) remaining."
                form.add_error(None, message)
            return self.form_invalid(form)
        auth_login(self.request, user)
        messages.success(self.request, "Signed in successfully.")
        return redirect(self.get_redirect_url())


def logout_view(request):
    if request.method != "POST":
        raise PermissionDenied("Logout requires a POST request.")
    auth_logout(request)
    messages.info(request, "You have been signed out.")
    return redirect(settings.LOGOUT_REDIRECT_URL)


class RegisterView(FormView):
    template_name = "accounts/register.html"
    form_class = RegistrationForm

    def dispatch(self, request, *args, **kwargs):
        if not settings.ALLOW_PUBLIC_REGISTRATION and not (request.user.is_authenticated and request.user.is_superuser):
            raise PermissionDenied("Public registration is disabled.")
        if request.user.is_authenticated:
            return redirect(settings.LOGIN_REDIRECT_URL)
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        data = form.cleaned_data
        user, organization = services.register_user(
            email=data["email"],
            username=data["username"],
            full_name=data["full_name"],
            password=data["password1"],
            organization_name=data["organization_name"],
            organization_slug=data.get("organization_slug") or None,
        )
        auth_login(self.request, user)
        self.request.session["active_organization_id"] = str(organization.pk)
        messages.success(self.request, "Your account and organization have been created.")
        return redirect("organizations:detail", pk=organization.pk)


class ProfileView(LoginRequiredMixin, UpdateView):
    template_name = "accounts/profile.html"
    form_class = ProfileForm
    success_url = reverse_lazy("accounts:profile")

    def get_object(self, queryset=None):
        return self.request.user

    def form_valid(self, form):
        services.update_profile(
            user=self.request.user,
            email=form.cleaned_data["email"],
            username=form.cleaned_data["username"],
            full_name=form.cleaned_data["full_name"],
        )
        messages.success(self.request, "Profile updated.")
        return HttpResponseRedirect(self.get_success_url())

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.setdefault(
            "memberships", self.request.user.memberships.select_related("organization").filter(is_active=True)
        )
        context.setdefault(
            "api_keys",
            services.list_api_keys(
                user=self.request.user,
                organization=getattr(self.request, "current_organization", None),
            ),
        )
        context.setdefault("api_key_form", ApiKeyCreateForm())
        return context


class ApiKeysView(OrganizationRoleRequiredMixin, TemplateView):
    template_name = "accounts/api_keys.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["api_keys"] = services.list_api_keys(
            user=self.request.user,
            organization=self.request.current_organization,
        )
        context["form"] = kwargs.get("form") or ApiKeyCreateForm()
        context["raw_key"] = self.request.session.pop("apishield_raw_api_key", None)
        return context


class ApiKeyCreateView(OrganizationRoleRequiredMixin, FormView):
    template_name = "accounts/api_keys.html"
    form_class = ApiKeyCreateForm
    success_url = reverse_lazy("accounts:api_keys")
    required_role = "developer"

    def form_valid(self, form):
        _, raw_key = services.create_api_key(
            user=self.request.user,
            organization=self.request.current_organization,
            name=form.cleaned_data["name"],
        )
        self.request.session["apishield_raw_api_key"] = raw_key
        messages.success(self.request, "API key created. Copy it now; it will not be shown again.")
        return HttpResponseRedirect(self.get_success_url())

    def form_invalid(self, form):
        return self.render_to_response(self.get_context_data(form=form))


class ApiKeyRevokeView(OrganizationRoleRequiredMixin, View):
    required_role = "developer"
    http_method_names = ["post"]

    def post(self, request, *args, **kwargs):
        api_key = get_object_or_404(
            ApiKey,
            pk=kwargs["pk"],
            user=request.user,
            organization=request.current_organization,
        )
        services.revoke_api_key(api_key=api_key, user=request.user)
        messages.success(self.request, f"API key {api_key.name} was revoked.")
        return redirect("accounts:api_keys")
