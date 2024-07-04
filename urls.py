from django.urls import path
from .import views
from .views import UserRegistration,LoginView,CreateUserView,LogoutView,UserDetailByEmailView,get_user_info
urlpatterns = [
    path('userRole/', views.ShowAll, name= 'userRole'),
    path('userRegister/', UserRegistration.as_view(), name='userRegister'),
    path('UserDetail/', CreateUserView.as_view(),name='UserDetail'),
    # path('logout/<str:id>/', LoginView.as_view(), name='logout'), # Define the URL pattern
    path('login/', LoginView.as_view(), name='login'),
    path('logout/<str:id>/', LogoutView.as_view(), name='logout'),
    path('user/<str:email>/', UserDetailByEmailView.as_view(), name='UserDataView'),
    path('user/<str:email>/', get_user_info, name='get_user_info'),

]