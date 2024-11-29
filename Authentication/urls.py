from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.Register, name='register'),
    path('login/', views.Login, name='login'),
    path('logout/', views.Logout, name='logout'),
    path('forgot-password/', views.ForgotPassword, name='forgot-password'),
    path('reset-password/<str:email>/<str:reset_code>/', views.ResetPassword, name='reset-password'),
    path('reset-password-from-profile/', views.ResetPasswordFromProfile, name='reset-password-from-profile'),
]