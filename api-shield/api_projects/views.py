from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, FormView, ListView, UpdateView

from accounts.permissions import OrganizationRoleRequiredMixin
from endpoint_discovery.services import import_openapi_spec

from . import services
from .forms import AuthorizationConfirmForm, ProjectForm, SpecUploadForm


class ProjectListView(OrganizationRoleRequiredMixin, ListView):
    template_name = "projects/list.html"
    context_object_name = "projects"

    def get_queryset(self):
        return services.get_projects_for_organization(
            self.request.current_organization,
            search=self.request.GET.get("q", ""),
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["search"] = self.request.GET.get("q", "")
        return context


class ProjectCreateView(OrganizationRoleRequiredMixin, CreateView):
    template_name = "projects/create.html"
    form_class = ProjectForm
    required_role = "analyst"

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["organization"] = self.request.current_organization
        return kwargs

    def form_valid(self, form):
        self.object = services.create_project(
            organization=self.request.current_organization,
            owner=self.request.user,
            **form.cleaned_data,
        )
        messages.success(self.request, "Project created.")
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return reverse_lazy("api_projects:detail", kwargs={"pk": self.object.pk})


class ProjectDetailView(OrganizationRoleRequiredMixin, DetailView):
    template_name = "projects/detail.html"
    context_object_name = "project"

    def get_queryset(self):
        return services.get_projects_for_organization(self.request.current_organization)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["scan_policy"] = getattr(self.object, "scan_policy", None)
        context["specifications"] = services.get_specifications_for_project(self.object)
        context["endpoints"] = self.object.endpoints.select_related("specification").prefetch_related(
            "endpoint_parameters"
        )
        context["authorization_form"] = kwargs.get("authorization_form") or AuthorizationConfirmForm()
        return context


class ProjectUpdateView(OrganizationRoleRequiredMixin, UpdateView):
    template_name = "projects/create.html"
    form_class = ProjectForm
    context_object_name = "project"
    required_role = "analyst"

    def get_queryset(self):
        return services.get_projects_for_organization(self.request.current_organization)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["organization"] = self.request.current_organization
        return kwargs

    def form_valid(self, form):
        services.update_project(project=self.object, data=form.cleaned_data)
        messages.success(self.request, "Project updated.")
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return reverse_lazy("api_projects:detail", kwargs={"pk": self.object.pk})


class ProjectDeleteView(OrganizationRoleRequiredMixin, DeleteView):
    template_name = "projects/detail.html"
    context_object_name = "project"
    success_url = reverse_lazy("api_projects:list")
    required_role = "admin"

    def get_queryset(self):
        return services.get_projects_for_organization(self.request.current_organization)

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        self.object.delete()
        messages.success(request, "Project deleted.")
        return HttpResponseRedirect(self.get_success_url())


class ProjectSpecUploadView(OrganizationRoleRequiredMixin, FormView):
    template_name = "projects/spec_upload.html"
    form_class = SpecUploadForm
    required_role = "analyst"

    def dispatch(self, request, *args, **kwargs):
        self.project = get_object_or_404(
            services.get_projects_for_organization(request.current_organization),
            pk=kwargs["pk"],
        )
        if not self.project.authorization_confirmed:
            raise PermissionDenied("Confirm authorization for this target before importing a specification.")
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project
        return context

    def form_valid(self, form):
        specification = import_openapi_spec(
            project=self.project,
            uploaded_file=form.cleaned_data.get("file"),
            content=form.cleaned_data.get("content") or None,
            name=form.cleaned_data.get("name") or None,
            imported_by=self.request.user,
        )
        messages.success(
            self.request,
            f"Imported {specification.endpoint_count} endpoint(s) from {specification.name}.",
        )
        return redirect("api_projects:detail", pk=self.project.pk)


class ProjectAuthorizationView(OrganizationRoleRequiredMixin, FormView):
    form_class = AuthorizationConfirmForm
    template_name = "projects/detail.html"
    required_role = "admin"
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        self.project = get_object_or_404(
            services.get_projects_for_organization(request.current_organization),
            pk=kwargs["pk"],
        )
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        services.confirm_authorization(
            project=self.project,
            reference=form.cleaned_data["authorization_reference"],
        )
        messages.success(self.request, "Authorization has been confirmed for this project.")
        return redirect("api_projects:detail", pk=self.project.pk)

    def form_invalid(self, form):
        return redirect("api_projects:detail", pk=self.project.pk)
