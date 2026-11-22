from .models import BroadcastAlert

def active_alerts(request):
    if request.user.is_authenticated:
        alerts = [alert for alert in BroadcastAlert.objects.filter(is_active=True) if alert.is_valid]
        return {'active_alerts': alerts}
    return {'active_alerts': []}
