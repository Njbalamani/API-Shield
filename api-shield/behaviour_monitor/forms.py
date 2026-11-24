from django import forms

from api_projects.models import ApiProject
from endpoint_discovery.models import ApiEndpoint

from .models import BehaviourAlert


class LogFilterForm(forms.Form):
    project = forms.ModelChoiceField(queryset=ApiProject.objects.none(), required=False, label="Project")
    method = forms.ChoiceField(choices=[("", "All methods")], required=False)
    suspicious_only = forms.BooleanField(required=False, label="Suspicious requests only")

    def __init__(self, organization, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["project"].queryset = ApiProject.objects.filter(organization=organization)
        self.fields["method"].choices = [("", "All methods"), *ApiEndpoint.Method.choices]


class AlertFilterForm(forms.Form):
    project = forms.ModelChoiceField(queryset=ApiProject.objects.none(), required=False, label="Project")
    alert_type = forms.ChoiceField(
        choices=[("", "All types"), *BehaviourAlert.AlertType.choices],
        required=False,
    )
    status = forms.ChoiceField(choices=[("", "All statuses"), *BehaviourAlert.Status.choices], required=False)
    severity = forms.ChoiceField(choices=[("", "All severities"), *BehaviourAlert.Severity.choices], required=False)

    def __init__(self, organization, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["project"].queryset = ApiProject.objects.filter(organization=organization)


class AlertActionForm(forms.Form):
    action = forms.ChoiceField(
        choices=(
            ("acknowledge", "Acknowledge"),
            ("resolve", "Resolve"),
        )
    )
