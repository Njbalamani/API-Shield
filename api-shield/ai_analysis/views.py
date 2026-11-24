from django.contrib import messages
from django.urls import reverse_lazy
from django.views.generic import DetailView, FormView, ListView

from accounts.permissions import OrganizationRoleRequiredMixin

from .forms import AiAnalyzeForm, AiFilterForm
from .models import AiAnalysis
from .services import analyze_finding, analyze_scan


class AiQuerysetMixin:
    def organization(self):
        return getattr(self.request, "current_organization", None)

    def scoped(self, queryset):
        organization = self.organization()
        return queryset.filter(organization=organization) if organization else queryset.none()


class AiAnalysisListView(OrganizationRoleRequiredMixin, AiQuerysetMixin, ListView):
    model = AiAnalysis
    template_name = "ai/list.html"
    context_object_name = "analyses"
    paginate_by = 25
    required_role = "viewer"

    def get_queryset(self):
        queryset = self.scoped(
            AiAnalysis.objects.select_related("finding", "finding__scan_run", "organization").order_by("-created_at")
        )
        priority = self.request.GET.get("priority")
        source = self.request.GET.get("source")
        if priority:
            queryset = queryset.filter(priority=priority)
        if source:
            queryset = queryset.filter(source=source)
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["filter_form"] = AiFilterForm(self.request.GET or None)
        return context


class AiAnalysisDetailView(OrganizationRoleRequiredMixin, AiQuerysetMixin, DetailView):
    model = AiAnalysis
    template_name = "ai/detail.html"
    context_object_name = "analysis"
    required_role = "viewer"

    def get_queryset(self):
        return self.scoped(AiAnalysis.objects.select_related("finding", "finding__scan_run", "organization"))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["finding"] = self.object.finding
        return context


class AiAnalyzeView(OrganizationRoleRequiredMixin, FormView):
    template_name = "ai/list.html"
    form_class = AiAnalyzeForm
    success_url = reverse_lazy("ai_analysis:list")
    required_role = "analyst"

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["organization"] = getattr(self.request, "current_organization", None)
        return kwargs

    def form_valid(self, form):
        finding = form.cleaned_data.get("finding")
        scan_run = form.cleaned_data.get("scan_run")
        if finding is not None:
            analysis = analyze_finding(finding)
            messages.success(self.request, f"AI analysis ready for finding #{analysis.finding_id}.")
        else:
            summary = analyze_scan(scan_run)
            messages.success(self.request, f"AI analysis completed for {summary['analyzed']} findings.")
        return super().form_valid(form)
