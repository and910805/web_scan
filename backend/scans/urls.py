from rest_framework.routers import DefaultRouter

from .views import IgnoreRuleViewSet, NotificationHookViewSet, ScanJobViewSet, ScheduledScanViewSet

router = DefaultRouter()
router.register("scans", ScanJobViewSet, basename="scan")
router.register("ignore-rules", IgnoreRuleViewSet, basename="ignore-rule")
router.register("scheduled-scans", ScheduledScanViewSet, basename="scheduled-scan")
router.register("notification-hooks", NotificationHookViewSet, basename="notification-hook")

urlpatterns = router.urls
