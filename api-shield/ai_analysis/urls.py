from django.urls import path

from . import views

app_name = "ai_analysis"

urlpatterns = [
    path("", views.AiAnalysisListView.as_view(), name="list"),
    path("analyze/", views.AiAnalyzeView.as_view(), name="analyze"),
    path("<int:pk>/", views.AiAnalysisDetailView.as_view(), name="detail"),
]
