"""TrustChain Flask Integration.

Provides extension and decorators for Flask applications.

Example:
    from flask import Flask
    from trustchain import TrustChain
    from trustchain.integrations.flask import TrustChainFlask, sign_response

    app = Flask(__name__)
    tc = TrustChain()

    # Option 1: Extension (with after_request hook)
    trustchain_ext = TrustChainFlask(app, trustchain=tc)

    # Option 2: Decorator (per-endpoint)
    @app.route('/api/tool', methods=['POST'])
    @sign_response(tc, 'my_tool')
    def endpoint():
        return {'result': 'data'}
"""

import functools
from typing import Any, Callable, Optional

try:
    from flask import Flask, Response, jsonify, request

    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False


class TrustChainFlask:
    """Flask extension for automatic response signing.

    Args:
        app: Flask application (optional, can call init_app later)
        trustchain: TrustChain instance
        sign_all: If True, sign all JSON responses. Default: False
        skip_paths: List of paths to skip signing
    """

    def __init__(
        self,
        app: Optional["Flask"] = None,
        trustchain: Any = None,
        sign_all: bool = False,
        skip_paths: Optional[list] = None,
    ):
        self.trustchain = trustchain
        self.sign_all = sign_all
        self.skip_paths = skip_paths or ["/static", "/health"]

        if app is not None:
            self.init_app(app)

    def init_app(self, app: "Flask") -> None:
        """Initialize Flask extension.

        Args:
            app: Flask application
        """
        if not HAS_FLASK:
            raise ImportError("Flask is required for TrustChainFlask")

        app.extensions["trustchain"] = self

        if self.sign_all:
            app.after_request(self._sign_response)

    def _sign_response(self, response: "Response") -> "Response":
        """After-request hook to sign JSON responses."""
        # Skip non-JSON
        if response.content_type != "application/json":
            return response

        # Skip certain paths
        if any(request.path.startswith(p) for p in self.skip_paths):
            return response

        # Check for skip header
        if request.headers.get("X-TrustChain-Skip"):
            return response

        try:
            # Parse and sign
            data = response.get_json()
            tool_id = request.headers.get("X-TrustChain-Tool", request.path)
            signed = self.trustchain.sign(tool_id, data)

            # Create new response
            new_response = jsonify(signed.to_dict())
            new_response.status_code = response.status_code
            new_response.headers["X-TrustChain-Signed"] = "true"
            new_response.headers["X-TrustChain-Key-ID"] = self.trustchain.get_key_id()

            return new_response

        except Exception:
            # On error, return original response
            return response


def sign_response(
    trustchain: Any, tool_id: str
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to sign individual endpoint responses.

    Args:
        trustchain: TrustChain instance
        tool_id: Identifier for this tool/endpoint

    Example:
        @app.route('/api/search', methods=['POST'])
        @sign_response(tc, 'search_api')
        def search():
            return {'results': [...]}
    """

    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Execute original function
            result = func(*args, **kwargs)

            # If already a Response, return as-is
            if isinstance(result, Response):
                return result

            # Sign the result
            signed = trustchain.sign(tool_id, result)

            response = jsonify(signed.to_dict())
            response.headers["X-TrustChain-Signed"] = "true"
            response.headers["X-TrustChain-Key-ID"] = trustchain.get_key_id()

            return response

        return wrapper

    return decorator


def get_public_key_endpoint(trustchain: Any) -> Callable[[], Any]:
    """Create a Flask endpoint that returns the public key.

    Example:
        app.add_url_rule(
            '/api/trustchain/public-key',
            'trustchain_public_key',
            get_public_key_endpoint(tc)
        )
    """

    def endpoint():
        return jsonify(
            {
                "public_key": trustchain.export_public_key(),
                "key_id": trustchain.get_key_id(),
                "algorithm": "ed25519",
            }
        )

    return endpoint
