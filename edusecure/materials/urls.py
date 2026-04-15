from django.urls import path
from . import views

urlpatterns = [
    path('',        views.list_materials, name='material_list'),
    path('upload/', views.upload_material, name='upload_material'),
]
