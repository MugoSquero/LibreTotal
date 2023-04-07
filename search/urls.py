from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('gui/search', views.PerformSearch, name='search'),
    path('api', views.api, name='api'),
]