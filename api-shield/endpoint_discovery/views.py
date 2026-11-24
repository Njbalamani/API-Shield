from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import DetailView, FormView, ListView

from accounts.permissions import OrganizationRoleRequiredMixin
from api_projects import services as project_services

from . import services
from .forms import DiscoverForm, EndpointFilterForm


class EndpointListView(OrganizationRoleRequiredMixin, ListView):
    template_name = "endpoints/list.html"
    context_object_name = "endpoints"

    def get_queryset(self):
        queryset = services.get_endpoints_for_organization(self.request.current_organization)
        self.filter_form = EndpointFilterForm(self.request.GET)
        if self.filter_form.is_valid():
            data = self.filter_form.cleaned_data
            term = data.get("q")
            if term:
                queryset = queryset.filter(
                    Q(path__icontains=term)
                    | Q(summary__icontains=term)
                    | Q(operation_id__icontains=term)
                    | Q(tags__icontains=term)
                )
            if data.get("method"):
                queryset = queryset.filter(method=data["method"])
            if data.get("risk_level"):
                queryset = queryset.filter(risk_level=data["risk_level"])
            if data.get("auth_required") == "yes":
                queryset = queryset.filter(auth_required=True)
            elif data.get("auth_required") == "no":
                queryset = queryset.filter(auth_required=False)
        project_id = self.request.GET.get("project")
        if project_id and str(project_id).isdigit():
            queryset = queryset.filter(project_id=int(project_id))
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["filter_form"] = getattr(self, "filter_form", EndpointFilterForm())
        context["risk_summary"] = services.risk_summary(organization=self.request.current_organization)
        project_id = self.request.GET.get("project")
        context["project"] = (
            project_services.get_project_for_organization(project_id, self.request.current_organization)
            if project_id
            else None
        )
        return context


class EndpointDetailView(OrganizationRoleRequiredMixin, DetailView):
    template_name = "endpoints/detail.html"
    context_object_name = "endpoint"

    def get_queryset(self):
        return services.get_endpoints_for_organization(self.request.current_organization)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["parameters"] = services.get_parameters_for_endpoint(self.object)
        return context


class EndpointDiscoverView(OrganizationRoleRequiredMixin, FormView):
    template_name = "endpoints/list.html"
    form_class = DiscoverForm
    success_url = reverse_lazy("endpoint_discovery:list")
    required_role = "analyst"

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["projects"] = project_services.get_projects_for_organization(self.request.current_organization)
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["endpoints"] = services.get_endpoints_for_organization(self.request.current_organization)
        context["filter_form"] = EndpointFilterForm()
        context["discover_form"] = kwargs.get("form") or self.get_form()
        return context

    def form_valid(self, form):
        project = form.cleaned_data["project"]
        try:
            summary = services.discover_endpoints(
                project=project,
                specification=form.cleaned_data.get("specification"),
                imported_by=self.request.user,
            )
        except ValidationError as exc:
            for message in exc.messages:
                form.add_error(None, message)
            return self.form_invalid(form)
        messages.success(
            self.request,
            f"Discovered {summary['endpoints']} endpoint(s) across {summary['specifications']} specification(s).",
        )
        return HttpResponseRedirect(f"{self.get_success_url()}?project={project.pk}")

    def form_invalid(self, form):
        return self.render_to_response(self.get_context_data(form=form))


class EndpointToggleView(OrganizationRoleRequiredMixin, DetailView):
    http_method_names = ["post"]
    required_role = "analyst"

    def get_queryset(self):
        return services.get_endpoints_for_organization(self.request.current_organization)

    def post(self, request, *args, **kwargs):
        endpoint = self.get_object()
        endpoint.is_active = not endpoint.is_active
        endpoint.save(update_fields=["is_active", "updated_at"])
        return redirect("endpoint_discovery:detail", pk=endpoint.pk)
