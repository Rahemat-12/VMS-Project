from rest_framework import serializers
from .models import UserRegister,UserLogin
from .models import UserRole
from django.contrib.auth import authenticate
import logging
logger = logging.getLogger('vmsApp.serializers')  # Get logger for this module
from django.utils import timezone

class UserSerializers(serializers.ModelSerializer):
    class Meta:
        model = UserRole
        fields = 'Id','role','description'


class userRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRegister
        fields = '__all__'
        # extra_kwargs = {'password': {'write_only': True}}

class userLoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserLogin
        fields = ('id','username','password', 'user_detail', 'user_role','active')
        # extra_kwargs = {'password': {'write_only': True}}







class UserSignIn(serializers.ModelSerializer):
    class Meta:
        model = UserLogin
        fields = ('username', 'password')

from django.contrib.auth.hashers import check_password  # For password verification

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, style={'input_type': 'password'})

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        try:
            user_login = UserLogin.objects.get(username=username)
            print("username", username)
            print("user_login", user_login)
            print("password", password)
            print("user_login.password", user_login.password)

        except UserLogin.DoesNotExist:
            logger.error("Invalid Username ")
            raise serializers.ValidationError('Invalid username.')

        if not check_password(password, user_login.password):  # Verify hashed password
            logger.error("Invalid Password ")
            raise serializers.ValidationError('Invalid password.')


        attrs['user_login'] = user_login
        return attrs



class CombinedDataSerializer(serializers.Serializer):
    user_register_data = serializers.SerializerMethodField()
    user_login_data = serializers.SerializerMethodField()
    user_role_data = serializers.SerializerMethodField()



    def get_user_register_data(self, obj):
        return obj.get('user_register')  # Access nested data from combined_data

    def get_user_login_data(self, obj):
        return obj.get('user_login')

    def get_user_role_data(self, obj):
        return obj.get('user_role')