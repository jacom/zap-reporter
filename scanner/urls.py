from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'targets', views.ScanTargetViewSet)
router.register(r'scans', views.ScanViewSet)
router.register(r'alerts', views.AlertViewSet, basename='alert')

urlpatterns = [
    path('', include(router.urls)),
    path('zap-status/', views.zap_status, name='api-zap-status'),
    path('tools-status/', views.tools_status, name='api-tools-status'),
    path('start-scan/', views.start_scan, name='api-start-scan'),
    path('owasp-summary/', views.owasp_summary, name='api-owasp-summary'),
    path('owasp-coverage/', views.owasp_coverage, name='api-owasp-coverage'),
    path('scans/<uuid:scan_id>/stop/', views.stop_scan, name='api-stop-scan'),
]
