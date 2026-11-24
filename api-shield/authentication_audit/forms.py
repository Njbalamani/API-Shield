from django import forms

from api_projects.models import ApiProject
from api_scanner.models import ScanRun

from .models import AuthenticationAudit


class AuditRunForm(forms.Form):
    project = forms.ModelChoiceField(queryset=ApiProject.objects.none(), label="Project")
    scan_run = forms.ModelChoiceField(queryset=ScanRun.objects.none(), required=False, label="Related scan")

    def __init__(self, *args, organization=None, **kwargs):
        super().__init__(*args, **kwargs)
        if organization is not None:
            self.fields["project"].queryset = ApiProject.objects.filter(organization=organization)
            self.fields["scan_run"].queryset = ScanRun.objects.filter(organization=organization)

    def clean(self):
        cleaned_data = super().clean()
        project = cleaned_data.get("project")
        scan_run = cleaned_data.get("scan_run")
        if project is not None and scan_run is not None and scan_run.project_id != project.id:
            raise forms.ValidationError("The selected scan does not belong to the selected project.")
        return cleaned_data


class AuditFilterForm(forms.Form):
    result = forms.ChoiceField(choices=[("", "Any result"), *AuthenticationAudit.Result.choices], required=False)
    auth_type = forms.ChoiceField(choices=[("", "Any scheme"), *AuthenticationAudit.AuthType.choices], required=False)
    project = forms.ModelChoiceField(queryset=ApiProject.objects.none(), required=False)

    def __init__(self, *args, organization=None, **kwargs):
        super().__init__(*args, **kwargs)
        if organization is not None:
            self.fields["project"].queryset = ApiProject.objects.filter(organization=organization)
