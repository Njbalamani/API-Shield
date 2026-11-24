from django import forms

from accounts.models import User
from organizations.models import Organization, OrganizationMembership


class OrganizationForm(forms.ModelForm):
    class Meta:
        model = Organization
        fields = ("name", "slug", "description")

    def clean_name(self):
        return self.cleaned_data["name"].strip()

    def clean_description(self):
        return self.cleaned_data["description"].strip()


class MemberAddForm(forms.Form):
    email = forms.EmailField(label="User email")
    role = forms.ChoiceField(choices=OrganizationMembership.Role.choices, label="Organization role")

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if not User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("No account exists with this email address.")
        return email

    def clean_role(self):
        role = self.cleaned_data["role"]
        if role not in set(OrganizationMembership.Role.values):
            raise forms.ValidationError("Select a valid organization role.")
        return role
