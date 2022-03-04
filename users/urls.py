from django.urls import path , include
from . import views
urlpatterns = [
    path('register', views.RegisterView.as_view(),name= "register"),
    path('activate/<slug:uidb64>/<slug:token>/', views.RegisterView.as_view(), name="active"),
    path('login', views.LoginView.as_view(), name= "login"),
    path('logout', views.LogoutView.as_view(), name= "logout"),
    path('', views.UserView.as_view(),name="user"),
    path('change-password', views.ChangePasswordView.as_view(),name="user")
]