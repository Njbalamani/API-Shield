from django import forms
from django.core.exceptions import ValidationError

from api_scanner.models import ScanRun

from .models import Report


class ReportGenerateForm(forms.ModelForm):
    parameters = forms.JSONField(required=False, initial=dict)

    class Meta:
        model = Report
        fields = ("report_type", "file_format", "project", "scan_run", "parameters")
        widgets = {"parameters": forms.Textarea(attrs={"rows": 5})}

    def __init__(self, organization, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.organization = organization
        self.fields["project"].queryset = organization.projects.all()
        self.fields["scan_run"].queryset = ScanRun.objects.filter(organization=organization)

    def clean_parameters(self):
        value = self.cleaned_data.get("parameters")
        return value if isinstance(value, dict) else {}

    def clean(self):
        cleaned_data = super().clean()
        project = cleaned_data.get("project")
        scan_run = cleaned_data.get("scan_run")
        if project and project.organization_id != self.organization.id:
            self.add_error("project", "Select a project in the current organization.")
        if scan_run:
            if scan_run.organization_id != self.organization.id:
                self.add_error("scan_run", "Select a scan run in the current organization.")
            elif project and scan_run.project_id != project.id:
                self.add_error("scan_run", "Select a scan run belonging to the chosen project.")
        if not project:
            raise ValidationError("A project is required.")
        return cleaned_data


class ReportFilterForm(forms.Form):
    report_type = forms.ChoiceField(choices=[("", "All types"), *Report.ReportType.choices], required=False)
    file_format = forms.ChoiceField(choices=[("", "All formats"), *Report.FileFormat.choices], required=False)
    status = forms.ChoiceField(choices=[("", "All statuses"), *Report.Status.choices], required=False)
    project = forms.ModelChoiceField(queryset=None, required=False)

    def __init__(self, organization, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["project"].queryset = organization.projects.all()
