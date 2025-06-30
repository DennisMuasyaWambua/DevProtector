
from django.urls import path
from . import views

urlpatterns = [
    path('projects/', views.ProjectCreate.as_view(), name='project-create'),
    path('projects/<uuid:uuid>/status/', views.ProjectStatus.as_view(), name='project-status'),
    path('projects/<uuid:uuid>/update/', views.ProjectUpdate.as_view(), name='project-update'),
]
