from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django.views.generic import FormView, ListView

from accounts.permissions import OrganizationRoleRequiredMixin

from . import services
from .forms import MemberAddForm
from .models import Organization


class OrganizationListView(LoginRequiredMixin, ListView):
    model = Organization
    template_name = "organizations/list.html"
    context_object_name = "organizations"

    def get_queryset(self):
        return services.get_user_organizations(self.request.user)


class OrganizationDetailView(OrganizationRoleRequiredMixin, ListView):
    template_name = "organizations/detail.html"
    context_object_name = "memberships"

    def get_queryset(self):
        return services.list_members(organization=self.request.current_organization)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["organization"] = self.request.current_organization
        context["member_form"] = kwargs.get("member_form") or MemberAddForm()
        context["can_manage"] = self.request.current_role == "admin" or self.request.user.is_superuser
        return context


class OrganizationSwitchView(LoginRequiredMixin, View):
    http_method_names = ["post"]

    def post(self, request, *args, **kwargs):
        organization_id = request.POST.get("organization_id")
        try:
            organization = services.switch_organization(user=request.user, organization_id=organization_id)
        except PermissionDenied:
            messages.error(request, "You are not a member of that organization.")
            return redirect("organizations:list")
        request.session["active_organization_id"] = str(organization.pk)
        messages.success(request, f"Active organization set to {organization.name}.")
        candidate = request.POST.get("next") or request.GET.get("next")
        if candidate and url_has_allowed_host_and_scheme(
            candidate,
            allowed_hosts={request.get_host()},
            require_https=request.is_secure(),
        ):
            return redirect(candidate)
        return redirect("organizations:list")


class OrganizationMembersView(OrganizationRoleRequiredMixin, ListView):
    template_name = "organizations/detail.html"
    context_object_name = "memberships"
    required_role = "analyst"

    def get_queryset(self):
        return services.list_members(organization=self.request.current_organization)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["organization"] = self.request.current_organization
        context["member_form"] = kwargs.get("member_form") or MemberAddForm()
        context["can_manage"] = self.request.current_role == "admin" or self.request.user.is_superuser
        return context


class OrganizationMemberAddView(OrganizationRoleRequiredMixin, FormView):
    template_name = "organizations/detail.html"
    form_class = MemberAddForm
    success_url = reverse_lazy("organizations:members")
    required_role = "admin"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["organization"] = self.request.current_organization
        context["memberships"] = services.list_members(organization=self.request.current_organization)
        context["member_form"] = kwargs.get("form") or MemberAddForm()
        context["can_manage"] = True
        return context

    def form_valid(self, form):
        services.add_member(
            organization=self.request.current_organization,
            email=form.cleaned_data["email"],
            role=form.cleaned_data["role"],
        )
        messages.success(self.request, "Organization member added.")
        return HttpResponseRedirect(self.get_success_url())

    def form_invalid(self, form):
        return self.render_to_response(self.get_context_data(form=form))


class OrganizationRemoveMemberView(OrganizationRoleRequiredMixin, View):
    required_role = "admin"
    http_method_names = ["post"]

    def post(self, request, *args, **kwargs):
        services.remove_member(organization=request.current_organization, membership_id=kwargs["pk"])
        messages.success(request, "Organization member removed.")
        return redirect("organizations:members")
