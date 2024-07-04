from django.contrib.auth.hashers import make_password
from django.db import models
import uuid
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver


class UserRole(models.Model):
    Id = models.CharField(max_length=50, primary_key=True)
    role = models.CharField(max_length=20)
    description = models.CharField(max_length=250)
    active = models.BooleanField(default=1)

    class Meta:
        db_table = 'USER_ROLE'


class UserRegister(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=50, db_column='FIRST_NAME')
    last_name = models.CharField(max_length=20, db_column='LAST_NAME')
    phone_number = models.CharField(default=0, max_length=15, db_column='PHONE_NUMBER')
    email = models.EmailField(unique=True, max_length=255)
    active = models.BooleanField(default=1)
    comment = models.CharField(max_length=512, default="")

    class Meta:
        db_table = 'USER_REGISTER'


class UserLogin(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=31, unique=True, db_column='USER_NAME')
    password = models.CharField(max_length=128, db_column='PASSWORD')

    def set_password(self, plain_text_password):
        self.password = make_password(plain_text_password)

    def save(self, *args, **kwargs):
        if self.password:
            self.password = make_password(self.password)  # Hash password before saving (in case it's modified)
        super().save(*args, **kwargs)

    user_detail = models.ForeignKey(UserRegister, on_delete=models.CASCADE, db_column='USER_DETAIL_ID')
    user_role = models.ForeignKey(UserRole, on_delete=models.CASCADE, db_column='USER_ROLE_ID')
    active = models.BooleanField(default=1)
    class Meta:
        db_table = 'USER_LOGIN'





class UserSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_login_id = models.ForeignKey(UserLogin, on_delete=models.CASCADE,db_column="USER_LOGIN_ID")  # Assuming a UserLogin model
    session_status = models.CharField(max_length=20)  # Options like 'active', 'inactive', etc.
    login_time = models.DateTimeField(blank=True, null=True)
    logout_time = models.DateTimeField(blank=True, null=True)


    class meta:
        db_table = 'USER_SESSION'


