from django import forms

from api_projects.models import ApiProject


class DashboardQueryForm(forms.Form):
    days = forms.IntegerField(min_value=1, max_value=365, required=False)
    include_inactive = forms.BooleanField(required=False)
    project = forms.ModelChoiceField(queryset=ApiProject.objects.none(), required=False)

    def __init__(self, organization, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if organization is not None:
            self.fields["project"].queryset = ApiProject.objects.filter(organization=organization)
