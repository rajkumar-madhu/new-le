from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse

PUBLIC_PREFIXES = ("/accounts/login/", "/static/", "/healthz",
                   # machine-to-machine endpoints; they authenticate with their own bearer token
                   "/api/v1/alertmanager/", "/api/v1/logs/")


class LoginRequiredMiddleware:
    """Every page needs a signed-in user; the login page, static files and the
    health endpoint are public. JSON API calls get 401 instead of a redirect."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated and not request.path.startswith(PUBLIC_PREFIXES):
            if "/api/" in request.path:
                from django.http import JsonResponse
                return JsonResponse({"error": "authentication required"}, status=401)
            return redirect(f"{reverse(settings.LOGIN_URL)}?next={request.get_full_path()}")
        return self.get_response(request)
