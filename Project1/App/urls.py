# App/urls.py
from django.urls import path
from .views import register, user_login, user_logout, home
from .views import submit_reclamation, view_reclamations


urlpatterns = [
    path('register/', register, name='register'),
    path('login/', user_login, name='login'),
    path('logout/', user_logout, name='logout'),
    path('home/', home, name='home'),  # Add this line
    path('submit_reclamation/', submit_reclamation, name='submit_reclamation'),
    path('view_reclamations/', view_reclamations, name='view_reclamations'),
]    

