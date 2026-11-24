from django import forms

from api_scanner.models import ScanFinding, ScanRun

from .models import AiAnalysis


class AiAnalyzeForm(forms.Form):
    finding = forms.ModelChoiceField(queryset=ScanFinding.objects.none(), required=False, label="Finding")
    scan_run = forms.ModelChoiceField(queryset=ScanRun.objects.none(), required=False, label="Scan")

    def __init__(self, *args, organization=None, **kwargs):
        super().__init__(*args, **kwargs)
        if organization is not None:
            self.fields["finding"].queryset = ScanFinding.objects.filter(scan_run__organization=organization)
            self.fields["scan_run"].queryset = ScanRun.objects.filter(organization=organization)

    def clean(self):
        cleaned_data = super().clean()
        finding = cleaned_data.get("finding")
        scan_run = cleaned_data.get("scan_run")
        if finding is None and scan_run is None:
            raise forms.ValidationError("Select a finding or a scan to analyze.")
        if finding is not None and scan_run is not None:
            raise forms.ValidationError("Select only one of finding or scan.")
        return cleaned_data


class AiFilterForm(forms.Form):
    priority = forms.ChoiceField(
        choices=[
            ("", "Any priority"),
            ("critical", "Critical"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
        ],
        required=False,
    )
    source = forms.ChoiceField(choices=[("", "Any source"), *AiAnalysis.Source.choices], required=False)
