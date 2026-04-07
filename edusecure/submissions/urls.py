from django.urls import path
from . import views

urlpatterns = [
    path('',       views.list_submissions, name='submission_list'),
    path('upload/', views.upload_submission, name='upload_submission'),
]
