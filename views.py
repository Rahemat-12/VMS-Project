from django.contrib.auth.models import User
from django.utils import timezone
from django.shortcuts import render
from rest_framework.authtoken.models import Token
from rest_framework.status import HTTP_401_UNAUTHORIZED, HTTP_200_OK, HTTP_400_BAD_REQUEST
from .serializers import UserSerializers,userRegisterSerializer,userLoginSerializer,CombinedDataSerializer
from .models import UserRole, UserSession, UserLogin,UserRegister
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status, settings
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from rest_framework import generics
from rest_framework.exceptions import NotFound
from django.db import connection






@api_view(['GET'])
def ShowAll(request):
    User_roless = UserRole.objects.all()
    serializer = UserSerializers(User_roless, many=True)
    return Response(serializer.data)


class UserRegistration(APIView):

    def post(self, request):
        if request.method == 'POST':
            logger = logging.getLogger('UserRegister')  # Use your view class name
            logger.info(f"Request data: {request.data}")
            print("Request data UserRegister: ", request.data)
            serializer = userRegisterSerializer(data=request.data)

            if serializer.is_valid():
                serializer.save()
                logger.info(f"New User Detail Register {timezone.localtime()},{UserRegister}")
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





class CreateUserView(APIView):
    def post(self, request):
        serializer = userRegisterSerializer(data=request.data)
        if serializer.is_valid():
            UserRegister = serializer.save()
            print("UserRegister Id: ", UserRegister.id)

            # Create User_login object with hashed password directly
            user_login_data = {
                'username': request.data['username'],
                'password': request.data['password'],
                'user_role': request.data['user_role_id'],
                'user_detail': str(UserRegister.id)  # Use PK from saved User_register
            }
            print("user_login_data: ", user_login_data)

            user_login_serializer = userLoginSerializer(data=user_login_data)
            if user_login_serializer.is_valid():
                user_login_serializer.save()  # Directly save UserLogin object
                logger.info("New User Registration Successful ")
                return Response("User registration successful", status=status.HTTP_201_CREATED)
            else:
                # Handle invalid UserLogin serializer errors
                logger.error("Invalid UserLogin ")
                return Response(user_login_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




from rest_framework.permissions import AllowAny
from .serializers import LoginSerializer
from django.contrib.auth import logout
from django.contrib.auth import logout  # For session logout
from django.utils import timezone
now = timezone.now()  # Assuming you're using django-timezone

logger = logging.getLogger('vmsApp.views')  # Get logger for this module

class LoginView(APIView):
    permission_classes = [AllowAny]  # Allow unauthenticated users for login

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_login = serializer.validated_data['user_login']
        logger.debug("User authenticated successfully ")

        if UserSession.objects.filter(user_login_id=user_login.id, session_status="ACTIVE").exists():
            logger.info(f"User Already Logged in: %s",user_login.id)
            return Response({'message': 'User already logged in'}, status=400)

        elif UserSession.objects.filter(user_login_id=user_login.id, session_status="INACTIVE").exists():
            # Get the existing UserSession object
            user_session = UserSession.objects.get(user_login_id=user_login.id)
            user_session.session_status = "ACTIVE"
            user_session.login_time = timezone.localtime()
            user_session.logout_time = None
            user_session.save()
            logger.info(f"User session updated to ACTIVE successfully %s:",user_login.id)  # Log session update
            return Response({'message': 'User Updated successful'}, status=200)

        userSessionInstance = UserSession()
        userSessionInstance.user_login_id = user_login
        userSessionInstance.session_status = "ACTIVE"
        userSessionInstance.login_time = timezone.localtime()
        userSessionInstance.logout_time= None
        print("timezone.localtime()", timezone.localtime())
        print("userSessionInstance: ", userSessionInstance)
        userSessionInstance.save()
        logger.info(f"User LogIn Successfully %s:",UserSession)
        return Response({'message': 'Login successful!'}, status=200)




class LogoutView(APIView):
    def post(self, request, id):
        try:
            user_session = UserSession.objects.get(id=id)
            user_session.session_status = "INACTIVE"
            user_session.logout_time = timezone.localtime()
            print("timezone.localtime()",timezone.localtime())
            user_session.save()
            logger.info(f"User LogOut successful Session Status : %s", user_session.session_status)
            return Response({'message': 'Logout successful!'}, status=HTTP_200_OK)
        except Exception as e:
            logger.error("An error occurred during logOut: %s", str(e))  # Log errors
            return Response({'message': 'User session not found.'}, status=HTTP_400_BAD_REQUEST)


# class UserDataView(APIView):
#
#     def get(self, request, email):
#         print('email:', email)
#         try:
#             User_Register = UserRegister.objects.get(email=email)  # Use primary key (pk) for ID lookup
#         except UserRegister.DoesNotExist:
#             raise NotFound  # Raise built-in exception for clarity
#         except Exception as e:  # Catch generic exceptions for logging
#             logger.error("An error occurred fetching user data: %s", str(e))
#             return Response({'error': 'An internal server error occurred.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#
#         serializer = userRegisterSerializer(User_Register)  # Use limited data serializer (single object)
#         logger.info(f"data fetch successful : %s",serializer.data)
#         return Response(serializer.data)

class UserDetailByEmailView(APIView):

    def get(self, request, email, format=None):
        try:
            user_register = UserRegister.objects.get(email=email)
            user_login = UserLogin.objects.get(user_detail=user_register.id)
            user_roles = UserRole.objects.get(role=user_login.user_role.role)
            user_register_serializer = userRegisterSerializer(user_register)
            user_login_serializer = userLoginSerializer(user_login)
            user_role_serializer = UserSerializers(user_roles)
            print("user_role_serializer",user_role_serializer.data['role'])

            combined_data = {
                'first_name': user_register_serializer.data['first_name'],
                'last_name': user_register_serializer.data['last_name'],
                'phone_number': user_register_serializer.data['phone_number'],
                'email': user_register_serializer.data['email'],
                'role': user_role_serializer.data['role'],
                'username': user_login_serializer.data['username'] if user_login else None,
                'password': user_login_serializer.data['password'],
            }


            return Response(combined_data, status=status.HTTP_200_OK)
        except UserRegister.DoesNotExist:
            return Response({'error': 'User not found in UserRegister'}, status=status.HTTP_404_NOT_FOUND)
        except UserLogin.DoesNotExist:
            return Response({'error': 'Corresponding UserLogin entry not found'}, status=status.HTTP_404_NOT_FOUND)




def get_user_info(email):
    """Fetches user information using a raw SQL query."""

    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT u.FIRST_NAME,u.LAST_NAME,u.phone_number,u.EMAIL, l.user_name,l.password, r.role"
            "FROM USER_REGISTER u"
            "JOIN USER_LOGIN l ON u.id = l.USER_DETAIL_ID"
            "JOIN USER_ROLE r ON l.USER_ROLE_ID = r.id"
            " WHERE u.email = '%s'",
            [email]
        )
        user_data = cursor.fetchone()  # Fetch the first row

    if user_data:
        return {
            'first_name': user_data[0],
            'last_name': user_data[1],
            'phone_number': user_data[2],
            'email': user_data[3],
            # Access other fields based on column order
            'username': user_data[4],
            'role': user_data[5],
        }
    else:
        return None  # Handle case where user not found