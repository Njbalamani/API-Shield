from django.contrib import messages
from django.urls import reverse_lazy
from django.views.generic import DetailView, FormView, ListView

from accounts.permissions import OrganizationRoleRequiredMixin

from .forms import ScanFilterForm, ScanFindingFilterForm, ScanStartForm
from .models import ScanFinding, ScanRun
from .services import create_scan, run_scan


class OrganizationQuerysetMixin:
    organization_field = "organization"

    def organization(self):
        return getattr(self.request, "current_organization", None)

    def scoped(self, queryset):
        organization = self.organization()
        lookup = self.organization_field
        return queryset.filter(**{lookup: organization}) if organization else queryset.none()


class ScanListView(OrganizationRoleRequiredMixin, OrganizationQuerysetMixin, ListView):
    model = ScanRun
    template_name = "scans/list.html"
    context_object_name = "scans"
    paginate_by = 25
    required_role = "viewer"

    def get_queryset(self):
        queryset = self.scoped(
            ScanRun.objects.select_related("project", "specification", "initiated_by").order_by("-started_at")
        )
        status = self.request.GET.get("status")
        mode = self.request.GET.get("mode")
        project_id = self.request.GET.get("project")
        if status:
            queryset = queryset.filter(status=status)
        if mode:
            queryset = queryset.filter(mode=mode)
        if project_id:
            queryset = queryset.filter(project_id=project_id)
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["filter_form"] = ScanFilterForm(self.request.GET or None, organization=self.organization())
        context["active_status"] = self.request.GET.get("status", "")
        context["active_mode"] = self.request.GET.get("mode", "")
        return context


class ScanStartView(OrganizationRoleRequiredMixin, FormView):
    template_name = "scans/start.html"
    form_class = ScanStartForm
    success_url = reverse_lazy("api_scanner:list")
    required_role = "analyst"

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["organization"] = getattr(self.request, "current_organization", None)
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        scan_run = create_scan(
            project=form.cleaned_data["project"],
            user=self.request.user,
            mode=form.cleaned_data["mode"],
            specification=form.cleaned_data.get("specification"),
        )
        run_scan(scan_run)
        self.scan_id = scan_run.pk
        messages.success(self.request, f"Scan #{scan_run.pk} completed with {scan_run.findings_count} findings.")
        return super().form_valid(form)

    def get_success_url(self):
        scan_id = getattr(self, "scan_id", None)
        if scan_id:
            return reverse_lazy("api_scanner:detail", kwargs={"pk": scan_id})
        return str(self.success_url)


class ScanDetailView(OrganizationRoleRequiredMixin, OrganizationQuerysetMixin, DetailView):
    model = ScanRun
    template_name = "scans/detail.html"
    context_object_name = "scan"
    required_role = "viewer"

    def get_queryset(self):
        return self.scoped(ScanRun.objects.select_related("project", "specification", "initiated_by"))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["logs"] = self.object.logs.all()
        context["findings"] = self.object.findings.select_related("endpoint", "rule")[:25]
        context["summary_notes"] = (self.object.summary or {}).get("notes", [])
        return context


class ScanFindingListView(OrganizationRoleRequiredMixin, OrganizationQuerysetMixin, ListView):
    model = ScanFinding
    template_name = "findings/list.html"
    context_object_name = "findings"
    paginate_by = 25
    organization_field = "scan_run__organization"
    required_role = "viewer"

    def get_queryset(self):
        queryset = self.scoped(
            ScanFinding.objects.select_related("scan_run", "endpoint", "rule").order_by("-risk_score", "-created_at")
        )
        scan_id = self.request.GET.get("scan_run")
        severity = self.request.GET.get("severity")
        status = self.request.GET.get("status")
        verified = self.request.GET.get("verified")
        if scan_id:
            queryset = queryset.filter(scan_run_id=scan_id)
        if severity:
            queryset = queryset.filter(severity=severity)
        if status:
            queryset = queryset.filter(status=status)
        if verified == "true":
            queryset = queryset.filter(verified=True)
        elif verified == "false":
            queryset = queryset.filter(verified=False)
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["filter_form"] = ScanFindingFilterForm(self.request.GET or None, organization=self.organization())
        return context


class ScanFindingDetailView(OrganizationRoleRequiredMixin, OrganizationQuerysetMixin, DetailView):
    model = ScanFinding
    template_name = "findings/detail.html"
    context_object_name = "finding"
    organization_field = "scan_run__organization"
    required_role = "viewer"

    def get_queryset(self):
        return self.scoped(ScanFinding.objects.select_related("scan_run", "endpoint", "rule"))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["ai_analysis"] = getattr(self.object, "ai_analysis", None)
        return context
