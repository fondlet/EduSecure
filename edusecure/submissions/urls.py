from django.urls import path

from . import views

urlpatterns = [
    path('',                  views.list_submissions,  name='submission_list'),
    path('upload/',           views.upload_submission, name='upload_submission'),
    path('assignments/',      views.list_assignments,  name='list_assignments'),
    path('assignments/new/',  views.create_assignment, name='create_assignment'),
    path('late/',             views.late_report,       name='late_report'),
]
