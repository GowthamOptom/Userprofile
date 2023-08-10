from django.urls import path
from arkapp import views

urlpatterns = [
    path('', views.index,name='index')
]
