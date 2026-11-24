from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.serializers.json import DjangoJSONEncoder
from django.http import JsonResponse
from django.views.generic import TemplateView

from accounts.permissions import OrganizationRoleRequiredMixin

from .forms import DashboardQueryForm
from .services import get_metrics, get_topology


def _options(request):
    organization = getattr(request, "current_organization", None)
    form = DashboardQueryForm(organization, request.GET)
    if form.is_valid():
        cleaned = form.cleaned_data
        return {
            "organization": organization,
            "form": form,
            "days": cleaned.get("days") or 7,
            "include_inactive": cleaned.get("include_inactive", False),
            "project": cleaned.get("project"),
        }
    return {
        "organization": organization,
        "form": form,
        "days": 7,
        "include_inactive": False,
        "project": None,
    }


class DashboardIndexView(LoginRequiredMixin, OrganizationRoleRequiredMixin, TemplateView):
    template_name = "dashboard/index.html"
    required_role = "viewer"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        options = _options(self.request)
        context["filter_form"] = options["form"]
        context["metrics"] = get_metrics(options["organization"], options["days"])
        context["topology"] = get_topology(
            options["organization"],
            include_inactive=options["include_inactive"],
            project=options["project"],
        )
        context["trend_days"] = options["days"]
        return context


class DashboardMetricsJsonView(LoginRequiredMixin, OrganizationRoleRequiredMixin, TemplateView):
    required_role = "viewer"

    def get(self, request, *args, **kwargs):
        options = _options(request)
        return JsonResponse(get_metrics(options["organization"], options["days"]), encoder=DjangoJSONEncoder)


class DashboardTopologyJsonView(LoginRequiredMixin, OrganizationRoleRequiredMixin, TemplateView):
    required_role = "viewer"

    def get(self, request, *args, **kwargs):
        options = _options(request)
        topology = get_topology(
            options["organization"],
            include_inactive=options["include_inactive"],
            project=options["project"],
        )
        return JsonResponse(topology, encoder=DjangoJSONEncoder)
