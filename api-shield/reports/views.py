from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import FileResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.views.generic import ListView, View

from accounts.permissions import OrganizationRoleRequiredMixin

from .forms import ReportFilterForm, ReportGenerateForm
from .models import Report
from .services import create_report, report_download


class ReportListView(LoginRequiredMixin, OrganizationRoleRequiredMixin, ListView):
    template_name = "reports/list.html"
    context_object_name = "reports"
    paginate_by = 25
    required_role = "analyst"

    def get_queryset(self):
        organization = getattr(self.request, "current_organization", None)
        if organization is None:
            return Report.objects.none()
        queryset = Report.objects.filter(organization=organization).select_related("project", "scan_run", "created_by")
        self.form = ReportFilterForm(organization, self.request.GET)
        if self.form.is_valid():
            for field in ("report_type", "file_format", "status", "project"):
                value = self.form.cleaned_data[field]
                if value:
                    queryset = queryset.filter(**{field: value})
        return queryset.order_by("-created_at")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        organization = getattr(self.request, "current_organization", None)
        context["filter_form"] = getattr(self, "form", ReportFilterForm(organization))
        context["generate_form"] = ReportGenerateForm(organization)
        context["completed_count"] = (
            Report.objects.filter(organization=organization, status=Report.Status.COMPLETED).count()
            if organization
            else 0
        )
        context["failed_count"] = (
            Report.objects.filter(organization=organization, status=Report.Status.FAILED).count() if organization else 0
        )
        return context


class ReportGenerateView(LoginRequiredMixin, OrganizationRoleRequiredMixin, View):
    template_name = "reports/generate.html"
    required_role = "analyst"

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name, {"form": ReportGenerateForm(request.current_organization)})

    def post(self, request, *args, **kwargs):
        form = ReportGenerateForm(request.current_organization, request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})
        cleaned = form.cleaned_data
        try:
            report = create_report(
                request.current_organization,
                cleaned["project"],
                created_by=request.user,
                report_type=cleaned["report_type"],
                file_format=cleaned["file_format"],
                scan_run=cleaned.get("scan_run"),
                parameters=cleaned.get("parameters"),
            )
        except Exception:
            messages.error(request, "The report could not be created. Check the selected project and scan.")
            return render(request, self.template_name, {"form": form})
        if report.status == Report.Status.COMPLETED:
            messages.success(request, "Report generated successfully.")
        else:
            messages.error(request, f"Report generation failed: {report.error_message}")
        return HttpResponseRedirect(reverse("reports:list"))


class ReportDownloadView(LoginRequiredMixin, OrganizationRoleRequiredMixin, View):
    required_role = "viewer"

    def get(self, request, *args, **kwargs):
        organization = getattr(request, "current_organization", None)
        report = Report.objects.filter(pk=kwargs["pk"], organization=organization).first() if organization else None
        if report is None or not report.file:
            messages.error(request, "Report not found in the current organization.")
            return HttpResponseRedirect(reverse("reports:list"))
        try:
            file_object, filename, content_type = report_download(report)
        except (FileNotFoundError, ValueError):
            messages.error(request, "The report file is not available.")
            return HttpResponseRedirect(reverse("reports:list"))
        return FileResponse(file_object, as_attachment=True, filename=filename, content_type=content_type)
