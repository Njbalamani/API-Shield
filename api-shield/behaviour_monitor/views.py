from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.views.generic import DetailView, ListView, View

from accounts.permissions import OrganizationRoleRequiredMixin

from .forms import AlertActionForm, AlertFilterForm, LogFilterForm
from .models import ApiRequestLog, BehaviourAlert
from .services import update_alert_status


class ScopedBehaviourMixin:
    def scoped_logs(self):
        organization = getattr(self.request, "current_organization", None)
        if organization is None:
            return ApiRequestLog.objects.none()
        return ApiRequestLog.objects.filter(organization=organization).select_related("project", "endpoint")

    def scoped_alerts(self):
        organization = getattr(self.request, "current_organization", None)
        if organization is None:
            return BehaviourAlert.objects.none()
        return BehaviourAlert.objects.filter(organization=organization).select_related("project", "endpoint")


class RequestLogListView(LoginRequiredMixin, OrganizationRoleRequiredMixin, ScopedBehaviourMixin, ListView):
    template_name = "alerts/logs.html"
    context_object_name = "logs"
    paginate_by = 25
    required_role = "analyst"

    def get_queryset(self):
        queryset = self.scoped_logs()
        self.form = LogFilterForm(self.request.current_organization, self.request.GET)
        if self.form.is_valid():
            filters = self.form.cleaned_data
            if filters["project"]:
                queryset = queryset.filter(project=filters["project"])
            if filters["method"]:
                queryset = queryset.filter(method=filters["method"])
            if filters["suspicious_only"]:
                queryset = queryset.filter(is_suspicious=True)
        return queryset.order_by("-timestamp")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["filter_form"] = getattr(self, "form", LogFilterForm(self.request.current_organization))
        context["suspicious_count"] = self.scoped_logs().filter(is_suspicious=True).count()
        context["total_count"] = self.scoped_logs().count()
        return context


class BehaviourAlertListView(LoginRequiredMixin, OrganizationRoleRequiredMixin, ScopedBehaviourMixin, ListView):
    template_name = "alerts/list.html"
    context_object_name = "alerts"
    paginate_by = 25
    required_role = "analyst"

    def get_queryset(self):
        queryset = self.scoped_alerts()
        self.form = AlertFilterForm(self.request.current_organization, self.request.GET)
        if self.form.is_valid():
            filters = self.form.cleaned_data
            for field in ("project", "alert_type", "status", "severity"):
                if filters[field]:
                    queryset = queryset.filter(**{field: filters[field]})
        return queryset.order_by("-created_at")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["filter_form"] = getattr(self, "form", AlertFilterForm(self.request.current_organization))
        context["open_count"] = self.scoped_alerts().filter(status=BehaviourAlert.Status.OPEN).count()
        context["acknowledged_count"] = self.scoped_alerts().filter(status=BehaviourAlert.Status.ACKNOWLEDGED).count()
        return context


class BehaviourAlertDetailView(LoginRequiredMixin, OrganizationRoleRequiredMixin, ScopedBehaviourMixin, DetailView):
    template_name = "alerts/detail.html"
    context_object_name = "alert"
    required_role = "analyst"

    def get_queryset(self):
        return self.scoped_alerts()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["action_form"] = AlertActionForm()
        context["related_logs"] = self.scoped_logs().filter(
            project=self.object.project, path=self.object.evidence.get("path", "")
        )[:10]
        if not self.object.evidence.get("path"):
            context["related_logs"] = self.scoped_logs().filter(project=self.object.project)[:10]
        return context

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        form = AlertActionForm(request.POST)
        if not form.is_valid():
            context = self.get_context_data(object=self.object)
            context["action_form"] = form
            return self.render_to_response(context)
        return self._apply_action(self.object, form.cleaned_data["action"])

    def _apply_action(self, alert, action):
        status = BehaviourAlert.Status.ACKNOWLEDGED if action == "acknowledge" else BehaviourAlert.Status.RESOLVED
        update_alert_status(alert, status, self.request.user)
        messages.success(self.request, f"Alert marked as {alert.get_status_display().lower()}.")
        return HttpResponseRedirect(reverse("behaviour_monitor:alert_detail", args=[alert.pk]))


class AlertStatusActionView(LoginRequiredMixin, OrganizationRoleRequiredMixin, ScopedBehaviourMixin, View):
    target_status = BehaviourAlert.Status.ACKNOWLEDGED
    required_role = "analyst"

    def post(self, request, *args, **kwargs):
        alert = self.scoped_alerts().filter(pk=kwargs["pk"]).first()
        if alert is None:
            messages.error(request, "Alert not found in the current organization.")
            return HttpResponseRedirect(reverse("behaviour_monitor:alerts"))
        update_alert_status(alert, self.target_status, request.user)
        messages.success(request, f"Alert marked as {alert.get_status_display().lower()}.")
        return HttpResponseRedirect(reverse("behaviour_monitor:alert_detail", args=[alert.pk]))


class AlertAcknowledgeView(AlertStatusActionView):
    target_status = BehaviourAlert.Status.ACKNOWLEDGED


class AlertResolveView(AlertStatusActionView):
    target_status = BehaviourAlert.Status.RESOLVED
