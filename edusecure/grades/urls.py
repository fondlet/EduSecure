from django.urls import path
from . import views

urlpatterns = [
    path('',                          views.all_submissions,  name='all_submissions'),
    path('<int:submission_id>/grade/', views.grade_submission, name='grade_submission'),
    path('<int:submission_id>/edit/',  views.edit_grade,       name='edit_grade'),
    path('my/',                        views.my_grades,        name='my_grades'),
]
