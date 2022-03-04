from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework import  serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from .models import UserBase
from django_countries.fields import CountryField
from PhotoGear.configs import jwt_config
from rest_framework.response import  Response
from rest_framework import status
from  cart.serializers import CartSerializer , OrderSerializer

class RegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = UserBase
        fields = ['email', 'user_name', 'password', 'password2', 'phone_number']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def save(self):
        account = UserBase(
            email=self.validated_data['email'],
            user_name=self.validated_data['user_name'],
            phone_number = self.validated_data['phone_number']
        )

        password = self.validated_data['password']
        password2 = self.validated_data['password2']

        if password != password2:
            raise serializers.ValidationError({'password': 'Your password not match'})

        account.set_password(password)
        account.is_active = True
        account.save()
        return account

class UserSerializer(serializers.ModelSerializer):
    class Meta :
        model = UserBase
        fields = ["email", "user_name", "phone_number"]

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)

    def login(self, request):
        email = self.validated_data["email"].lower()
        password = self.validated_data["password"]
        exist = UserBase.objects.filter(email=email).exists()
        if(exist) :
            user = authenticate(request, email=email, password=password)
            if (user):
                refresh = TokenObtainPairSerializer.get_token(user)
                data = {
                    'msg' : "Login Success",
                    'refresh_token': str(refresh),
                    'access_token': str(refresh.access_token),
                    'access_expires': int(jwt_config.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()),
                    'refresh_expires': int(jwt_config.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds())
                }
                response = Response(data, status=status.HTTP_200_OK)
                # response.set_cookie("access_token", str(refresh.access_token))
                return response
            return Response({'msg': 'Invalid password, please try again', 'status': '400'},
                            status=status.HTTP_200_OK)

        return Response({"msg":"User does not exist", "status":"400"},status=status.HTTP_200_OK)

class changePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    new_password_confirm= serializers.CharField(required=True)

    def changePassword(self, request):
        email = request.user.email
        authen = authenticate (request, email=email, password= request.data["password"])
        if(authen):
            if (request.data["new_password"] != request.data["new_password_confirm"]):
                return Response({"msg":"Password does not match", "status":"400"},status=status.HTTP_400_BAD_REQUEST)
            user= UserBase.objects.get(email=email) 
            user.set_password(request.data["new_password"])
            user.save()
            return Response({"msg": "Change Password success"},status=status.HTTP_200_OK)
            
        else:
            return Response({"msg":"Invalid password", "status":"400"},status=status.HTTP_400_BAD_REQUEST)




class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {
        'bad_token' : ('Token is expired or invalid')
    }

    def validate(self,attr):
        self.token= attr['refresh']

        return attr
    def save(self, **kwargs):

        try:
            RefreshToken(self.token).blacklist()

        except TokenError:
            self.fail('bad_token')