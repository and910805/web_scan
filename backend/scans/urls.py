from rest_framework.routers import DefaultRouter

from .views import ScanJobViewSet

router = DefaultRouter()
router.register("scans", ScanJobViewSet, basename="scan")

urlpatterns = router.urls
