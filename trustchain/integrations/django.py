"""TrustChain Django Integration.

Provides middleware and decorator for Django applications.

Example:
    # settings.py
    MIDDLEWARE = [
        ...
        'trustchain.integrations.django.TrustChainMiddleware',
    ]

    TRUSTCHAIN_CONFIG = {
        'SIGN_ALL': True,
        'SKIP_PATHS': ['/admin/', '/static/'],
    }

    # views.py
    from trustchain.integrations.django import sign_response

    @sign_response(tc, 'my_tool')
    def my_view(request):
        return JsonResponse({'result': 'data'})
"""

import functools
import json
from typing import Callable

try:
    from django.conf import settings
    from django.http import HttpRequest, HttpResponse, JsonResponse

    HAS_DJANGO = True
except ImportError:
    HAS_DJANGO = False


class TrustChainMiddleware:
    """Django middleware for automatic response signing.

    Add to MIDDLEWARE in settings.py:
        'trustchain.integrations.django.TrustChainMiddleware'

    Configure via TRUSTCHAIN_CONFIG in settings:
        TRUSTCHAIN_CONFIG = {
            'SIGN_ALL': True,  # Sign all JSON responses
            'SKIP_PATHS': ['/admin/', '/static/', '/health/'],
        }
    """

    def __init__(self, get_response: Callable):
        if not HAS_DJANGO:
            raise ImportError("Django is required for TrustChainMiddleware")

        self.get_response = get_response

        # Get config from settings
        self.config = getattr(settings, "TRUSTCHAIN_CONFIG", {})
        self.sign_all = self.config.get("SIGN_ALL", False)
        self.skip_paths = self.config.get("SKIP_PATHS", ["/admin/", "/static/"])

        # Get or create TrustChain instance
        self.trustchain = self.config.get("TRUSTCHAIN_INSTANCE", None)
        if not self.trustchain:
            from trustchain import TrustChain

            self.trustchain = TrustChain()

    def __call__(self, request: "HttpRequest") -> "HttpResponse":
        response = self.get_response(request)

        # Only process if sign_all is True
        if not self.sign_all:
            return response

        # Skip certain paths
        if any(request.path.startswith(p) for p in self.skip_paths):
            return response

        # Check for skip header
        if request.headers.get("X-TrustChain-Skip"):
            return response

        # Only sign JSON responses
        content_type = response.get("Content-Type", "")
        if "application/json" not in content_type:
            return response

        try:
            # Parse response content
            data = json.loads(response.content.decode("utf-8"))

            # Get tool_id from header or path
            tool_id = request.headers.get("X-TrustChain-Tool", request.path)

            # Sign the data
            signed = self.trustchain.sign(tool_id, data)

            # Create new response
            new_response = JsonResponse(signed.to_dict())
            new_response.status_code = response.status_code

            # Add headers
            new_response["X-TrustChain-Signed"] = "true"
            new_response["X-TrustChain-Key-ID"] = self.trustchain.get_key_id()

            return new_response

        except Exception:
            # On error, return original response
            return response


def sign_response(trustchain, tool_id: str):
    """Decorator to sign individual view responses.

    Args:
        trustchain: TrustChain instance
        tool_id: Identifier for this tool/endpoint

    Example:
        @sign_response(tc, 'search_api')
        def search(request):
            return JsonResponse({'results': [...]})
    """

    def decorator(view_func: Callable):
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Execute original view
            response = view_func(request, *args, **kwargs)

            # If not JsonResponse, return as-is
            if not isinstance(response, JsonResponse):
                return response

            try:
                # Parse JSON data
                data = json.loads(response.content.decode("utf-8"))

                # Sign the data
                signed = trustchain.sign(tool_id, data)

                # Create new response
                new_response = JsonResponse(signed.to_dict())
                new_response.status_code = response.status_code

                # Add headers
                new_response["X-TrustChain-Signed"] = "true"
                new_response["X-TrustChain-Key-ID"] = trustchain.get_key_id()

                return new_response

            except Exception:
                return response

        return wrapper

    return decorator


def get_public_key_view(trustchain):
    """Create a Django view that returns the public key.

    Example:
        # urls.py
        from trustchain.integrations.django import get_public_key_view

        urlpatterns = [
            path('api/trustchain/public-key/', get_public_key_view(tc)),
        ]
    """

    def view(request):
        return JsonResponse(
            {
                "public_key": trustchain.export_public_key(),
                "key_id": trustchain.get_key_id(),
                "algorithm": "ed25519",
            }
        )

    return view


# Django REST Framework integration (optional)
try:
    from rest_framework.response import Response

    HAS_DRF = True
except ImportError:
    HAS_DRF = False
    Response = None


def sign_drf_response(trustchain, tool_id: str):
    """Decorator for Django REST Framework views.

    Example:
        @api_view(['POST'])
        @sign_drf_response(tc, 'search_api')
        def search(request):
            return Response({'results': [...]})
    """

    def decorator(view_func: Callable):
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            response = view_func(request, *args, **kwargs)

            if not HAS_DRF or not isinstance(response, Response):
                return response

            try:
                # Sign the data
                signed = trustchain.sign(tool_id, response.data)

                # Update response
                response.data = signed.to_dict()
                response["X-TrustChain-Signed"] = "true"
                response["X-TrustChain-Key-ID"] = trustchain.get_key_id()

                return response

            except Exception:
                return response

        return wrapper

    return decorator
