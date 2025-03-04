from django.contrib.auth.models import User
from rest_framework import viewsets, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .serializers import UserSerializer, RegisterSerializer ,LoginSerializer ,ChangePasswordSerializer,ResetPasswordSerializer  
from rest_framework_simplejwt.tokens import RefreshToken


class UserViewSet(viewsets.ModelViewSet):
    """
    User-related operations
    -(register)
    -(login)
    -(logout)
    -(me)
    -(change_password)
    -(reset_password)
    -(update_profile)
    """
    queryset = User.objects.all()   
    def get_serializer_class(self):
        if self.action == 'register':
            return UserSerializer
        elif self.action == 'login':
            return LoginSerializer
        elif self.action == 'change_password':
            return ChangePasswordSerializer
        return LoginSerializer  

    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return User.objects.filter(id=self.request.user.id)
    
    @action(detail=False, methods=['post'], permission_classes=[permissions.AllowAny])
    def register(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        return Response(serializer.errors, status=400)
    
    @action(detail=False, methods=['post'], permission_classes=[permissions.AllowAny])
    def login(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        user = authenticate(username=username, password=password)

        if user is not None:
            if not user.is_active:
                return Response({'error': 'User account is disabled'}, status=400)

            refresh = RefreshToken.for_user(user)
            return Response({
                'message': 'Login successful',
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })

        return Response({'error': 'Invalid username or password'}, status=400)
    
    @action(detail=False, methods=['post'], permission_classes=[permissions.IsAuthenticated])
    def logout(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response({'error': 'Refresh token is required'}, status=400)

            token = RefreshToken(refresh_token)
            token.blacklist() 
            return Response({'success': 'Logged out successfully'}, status=200)

        except Exception as e:
            return Response({'error': str(e)}, status=400)
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)
        
    @swagger_auto_schema(
    method='post',
    request_body=ChangePasswordSerializer,
    responses={200: openapi.Response('Password changed successfully')}
    )
    @action(detail=False, methods=['post'], permission_classes=[permissions.IsAuthenticated])
    def change_password(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            old_password = serializer.validated_data['old_password']
            new_password = serializer.validated_data['new_password']
            
            if not request.user.check_password(old_password):
                return Response({'error': 'Old password is incorrect'}, status=400)

            request.user.set_password(new_password)
            request.user.save()

            return Response({'success': 'Password changed successfully'})
        return Response(serializer.errors, status=400)
    
    @action(detail=False, methods=['post'], permission_classes=[permissions.AllowAny])
    def reset_password(self, request):
        """

        """
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)

            new_password = get_random_string(8)  
            user.set_password(new_password)
            user.save()

            send_mail(
                'Password Reset',
                f'Your new password is: {new_password}',
                'no-reply@example.com',
                [email],
                fail_silently=False,
            )

            return Response({'success': 'New password has been sent to your email'})

        return Response(serializer.errors, status=400)


