from django.contrib.auth.models import (AbstractBaseUser, PermissionsMixin, BaseUserManager)
from django.core.mail import send_mail
from django.db import models
from django.utils.translation import ugettext_lazy as _
from django_countries.fields import CountryField

# Create your models here.
class CustomAccountManager(BaseUserManager):

    def create_superuser(self, email, user_name, password, **other_fields):
        other_fields.setdefault('is_staff', True)
        other_fields.setdefault('is_superuser', True)
        other_fields.setdefault('is_active', True)

        if other_fields.get('is_staff') is not True:
            raise ValueError('Superuser must be assigned to is_staff = True')
        if other_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must be assigned to is_superuser = True')
        return self.create_user(email, user_name, password, **other_fields)

    def create_user(self, email, user_name, password,phone_number, **other_fields):

        if not email:
            raise ValueError(_('You must provide an email address'))
        email = self.normalize_email(email)

        user = self.model(email=email, user_name=user_name, phone_number=phone_number, **other_fields)
        user.set_password(password)
        user.save()
        return user

class UserBase(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(_('email address'), unique=True)
    user_name = models.CharField(max_length=150, unique=True)
    about = models.TextField(_('about'), max_length=150, blank=True)
    phone_number = models.CharField(max_length=15,  null=False)

    # User status
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    objects = CustomAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['user_name', 'phone_number']

    class Meta:
        verbose_name = "Accounts"
        verbose_name_plural = "Accounts"

    def __str__(self):
        return self.user_name

    def email_user(self, subject, message, from_email=None, **kwargs):
        """Send an email to this user."""
        send_mail(subject, message, from_email, [self.email], **kwargs)
