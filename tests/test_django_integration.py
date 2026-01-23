"""Tests for TrustChain Django Integration (Phase 16.1)."""

import pytest

# Skip if Django not installed
django = pytest.importorskip("django")

import json
from unittest.mock import MagicMock, patch

from trustchain import TrustChain, TrustChainConfig


class TestDjangoMiddleware:
    """Test suite for Django middleware."""

    def test_middleware_import(self):
        """Test Django middleware can be imported."""
        from trustchain.integrations.django import TrustChainMiddleware

        assert TrustChainMiddleware is not None

    def test_sign_response_decorator_import(self):
        """Test decorator can be imported."""
        from trustchain.integrations.django import sign_response

        assert sign_response is not None


class TestDjangoSignResponse:
    """Test suite for @sign_response decorator."""

    def test_decorator_exists(self):
        """Test decorator function exists."""
        from trustchain.integrations.django import sign_response

        tc = TrustChain(TrustChainConfig(enable_nonce=False))

        @sign_response(tc, "test_tool")
        def mock_view(request):
            from django.http import JsonResponse

            return JsonResponse({"result": "data"})

        assert callable(mock_view)


class TestPublicKeyView:
    """Test suite for public key view."""

    def test_get_public_key_view(self):
        """Test public key view function."""
        from trustchain.integrations.django import get_public_key_view

        tc = TrustChain()
        view = get_public_key_view(tc)

        assert callable(view)


class TestDRFIntegration:
    """Test suite for Django REST Framework integration."""

    def test_sign_drf_response_import(self):
        """Test DRF decorator can be imported."""
        from trustchain.integrations.django import sign_drf_response

        assert sign_drf_response is not None

    def test_drf_decorator_callable(self):
        """Test DRF decorator is callable."""
        from trustchain.integrations.django import sign_drf_response

        tc = TrustChain()

        @sign_drf_response(tc, "api_endpoint")
        def mock_view(request):
            return {"data": "test"}

        assert callable(mock_view)
