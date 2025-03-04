from django.urls import path, include,re_path
from rest_framework.routers import DefaultRouter
from .views import UserViewSet
from django.contrib import admin
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi


router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')

schema_view = get_schema_view(
    openapi.Info(
        title="My API",
        default_version='v1',
        description="API documentation",
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)



urlpatterns = [
    path('', include(router.urls)),
    path('admin/', admin.site.urls), 
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),

]

print(urlpatterns)
