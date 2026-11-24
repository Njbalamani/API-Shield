from django.contrib import messages
from django.urls import reverse_lazy
from django.views.generic import DetailView, FormView, ListView

from accounts.permissions import OrganizationRoleRequiredMixin

from .forms import AuditFilterForm, AuditRunForm
from .models import AuthenticationAudit
from .services import analyze_project


class AuditQuerysetMixin:
    def organization(self):
        return getattr(self.request, "current_organization", None)

    def scoped(self, queryset):
        organization = self.organization()
        return queryset.filter(organization=organization) if organization else queryset.none()


class AuthAuditListView(OrganizationRoleRequiredMixin, AuditQuerysetMixin, ListView):
    model = AuthenticationAudit
    template_name = "audits/list.html"
    context_object_name = "audits"
    paginate_by = 25
    required_role = "viewer"

    def get_queryset(self):
        queryset = self.scoped(
            AuthenticationAudit.objects.select_related("project", "endpoint", "scan_run").order_by("-created_at")
        )
        result = self.request.GET.get("result")
        auth_type = self.request.GET.get("auth_type")
        project_id = self.request.GET.get("project")
        if result:
            queryset = queryset.filter(result=result)
        if auth_type:
            queryset = queryset.filter(auth_type=auth_type)
        if project_id:
            queryset = queryset.filter(project_id=project_id)
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["filter_form"] = AuditFilterForm(self.request.GET or None, organization=self.organization())
        return context


class AuthAuditDetailView(OrganizationRoleRequiredMixin, AuditQuerysetMixin, DetailView):
    model = AuthenticationAudit
    template_name = "audits/detail.html"
    context_object_name = "audit"
    required_role = "viewer"

    def get_queryset(self):
        return self.scoped(AuthenticationAudit.objects.select_related("project", "endpoint", "scan_run"))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["token_tests"] = self.object.token_tests.all()
        return context


class AuthAuditRunView(OrganizationRoleRequiredMixin, FormView):
    template_name = "audits/list.html"
    form_class = AuditRunForm
    success_url = reverse_lazy("authentication_audit:list")
    required_role = "analyst"

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["organization"] = getattr(self.request, "current_organization", None)
        return kwargs

    def form_valid(self, form):
        summary = analyze_project(
            form.cleaned_data["project"],
            user=self.request.user,
            scan_run=form.cleaned_data.get("scan_run"),
        )
        messages.success(self.request, f"Authentication audit completed for {summary['audits_created']} operations.")
        return super().form_valid(form)
