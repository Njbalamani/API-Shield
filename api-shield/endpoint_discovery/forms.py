from django import forms

from api_projects.models import ApiProject, OpenApiSpecification

from .models import ApiEndpoint


class EndpointFilterForm(forms.Form):
    q = forms.CharField(required=False, label="Search")
    method = forms.ChoiceField(
        required=False,
        choices=[("", "All methods"), *ApiEndpoint.Method.choices],
    )
    risk_level = forms.ChoiceField(
        required=False,
        choices=[("", "All risk levels"), *ApiEndpoint.RiskLevel.choices],
    )
    auth_required = forms.ChoiceField(
        required=False,
        choices=[("", "Any authentication"), ("yes", "Authenticated"), ("no", "Unauthenticated")],
    )


class DiscoverForm(forms.Form):
    project = forms.ModelChoiceField(queryset=ApiProject.objects.none(), label="Project")
    specification = forms.ModelChoiceField(
        queryset=OpenApiSpecification.objects.none(),
        required=False,
        label="Specification (all if omitted)",
    )

    def __init__(self, *args, projects=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["project"].queryset = projects if projects is not None else ApiProject.objects.none()
        self.fields["specification"].queryset = OpenApiSpecification.objects.filter(
            project__in=self.fields["project"].queryset
        )

    def clean(self):
        cleaned = super().clean()
        project = cleaned.get("project")
        specification = cleaned.get("specification")
        if project is not None and specification is not None and specification.project_id != project.pk:
            self.add_error("specification", "Select a specification belonging to the chosen project.")
        return cleaned
