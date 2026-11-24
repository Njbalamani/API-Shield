from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator

from . import services
from .models import ApiProject


class ProjectForm(forms.ModelForm):
    authorization_confirmed = forms.BooleanField(required=False, label="I am authorized to test this target")

    class Meta:
        model = ApiProject
        fields = (
            "name",
            "slug",
            "description",
            "environment",
            "base_url",
            "authorization_confirmed",
            "authorization_reference",
        )

    def __init__(self, *args, organization=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.organization = organization
        self.fields["slug"].required = False

    def clean(self):
        cleaned = super().clean()
        data = dict(cleaned)
        if not data.get("slug"):
            data["slug"] = self.instance.slug if self.instance.pk else ""
        try:
            validated = services.validate_project_data(
                data,
                organization=self.organization,
                instance=self.instance if self.instance.pk else None,
            )
        except ValidationError as exc:
            for field, messages in exc.message_dict.items():
                self.add_error(None if field == forms.NON_FIELD_ERRORS else field, messages)
            return cleaned
        cleaned.update(validated)
        return cleaned


class SpecUploadForm(forms.Form):
    name = forms.CharField(max_length=180, required=False, label="Specification name")
    file = forms.FileField(
        required=False,
        label="Specification file",
        validators=[FileExtensionValidator(allowed_extensions=["json", "yaml", "yml", "txt"])],
    )
    content = forms.CharField(required=False, widget=forms.Textarea, label="Or paste specification content")

    def clean(self):
        cleaned = super().clean()
        uploaded = cleaned.get("file")
        content = (cleaned.get("content") or "").strip()
        if uploaded is not None and content:
            raise forms.ValidationError("Provide either a file or pasted content, not both.")
        if uploaded is None and not content:
            raise forms.ValidationError("Upload a JSON, YAML, or TXT file, or paste the specification content.")
        if uploaded is not None and uploaded.size > settings.DATA_UPLOAD_MAX_MEMORY_SIZE:
            raise forms.ValidationError("The specification file is too large.")
        cleaned["content"] = content
        return cleaned


class AuthorizationConfirmForm(forms.Form):
    authorization_reference = forms.CharField(max_length=200, label="Authorization reference")

    def clean_authorization_reference(self):
        return self.cleaned_data["authorization_reference"].strip()
