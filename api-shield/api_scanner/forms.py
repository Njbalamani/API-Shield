from django import forms
from django.core.exceptions import ValidationError

from accounts.permissions import has_minimum_role
from api_projects.models import ApiProject, OpenApiSpecification

from .models import ScanFinding, ScanRun


class ScanStartForm(forms.Form):
    project = forms.ModelChoiceField(queryset=ApiProject.objects.none(), label="Project")
    specification = forms.ModelChoiceField(
        queryset=OpenApiSpecification.objects.none(), required=False, label="Specification"
    )
    mode = forms.ChoiceField(choices=ScanRun.Mode.choices, initial=ScanRun.Mode.PASSIVE)

    def __init__(self, *args, organization=None, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.organization = organization
        self.user = user
        if organization is not None:
            self.fields["project"].queryset = ApiProject.objects.filter(
                organization=organization, status=ApiProject.Status.ACTIVE
            )
            self.fields["specification"].queryset = OpenApiSpecification.objects.filter(
                project__organization=organization
            )

    def clean(self):
        cleaned_data = super().clean()
        project = cleaned_data.get("project")
        specification = cleaned_data.get("specification")
        if project is not None and not has_minimum_role(self.user, project.organization, "analyst"):
            raise ValidationError("You do not have permission to scan this organization.")
        if project is not None and specification is not None and specification.project_id != project.id:
            raise ValidationError("The selected specification does not belong to the selected project.")
        if project is not None:
            policy = getattr(project, "scan_policy", None)
            if policy is not None and not policy.allow_passive_tests:
                raise ValidationError("The project scan policy does not allow passive analysis.")
        return cleaned_data


class ScanFilterForm(forms.Form):
    status = forms.ChoiceField(choices=[("", "Any status"), *ScanRun.Status.choices], required=False)
    mode = forms.ChoiceField(choices=[("", "Any mode"), *ScanRun.Mode.choices], required=False)
    project = forms.ModelChoiceField(queryset=ApiProject.objects.none(), required=False)

    def __init__(self, *args, organization=None, **kwargs):
        super().__init__(*args, **kwargs)
        if organization is not None:
            self.fields["project"].queryset = ApiProject.objects.filter(organization=organization)


class ScanFindingFilterForm(forms.Form):
    scan_run = forms.ModelChoiceField(queryset=ScanRun.objects.none(), required=False)
    severity = forms.ChoiceField(choices=[("", "Any severity"), *ScanFinding.Severity.choices], required=False)
    status = forms.ChoiceField(choices=[("", "Any status"), *ScanFinding.Status.choices], required=False)
    verified = forms.ChoiceField(
        choices=[("", "Any verification"), ("true", "Verified"), ("false", "Unverified")],
        required=False,
    )

    def __init__(self, *args, organization=None, **kwargs):
        super().__init__(*args, **kwargs)
        if organization is not None:
            self.fields["scan_run"].queryset = ScanRun.objects.filter(organization=organization)
