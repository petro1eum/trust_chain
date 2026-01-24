"""pytest plugin for TrustChain.

Provides:
    - Automatic fixture registration
    - @pytest.mark.trustchain_verify marker
    - --trustchain-report option for HTML reports
"""

import pytest

from trustchain import SignedResponse, TrustChain

from .fixtures import SignedChainCollector, async_tc, signed_chain, tc

# Fixtures are imported above and re-exported via __all__ at the bottom


def pytest_addoption(parser):
    """Add command line options."""
    group = parser.getgroup("trustchain")
    group.addoption(
        "--trustchain-report",
        action="store",
        dest="trustchain_report",
        default=None,
        metavar="PATH",
        help="Generate TrustChain verification report at PATH",
    )
    group.addoption(
        "--trustchain-strict",
        action="store_true",
        dest="trustchain_strict",
        default=False,
        help="Fail tests if SignedResponse verification fails",
    )


class TrustChainPlugin:
    """Main pytest plugin class.

    Tracks all SignedResponses created during test session
    and generates reports.
    """

    def __init__(self, config):
        self.config = config
        self.tc = TrustChain()
        self.responses: list = []
        self.test_results: dict = {}

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_call(self, item):
        """Wrap test execution to capture SignedResponses."""
        # Check for trustchain_verify marker
        marker = item.get_closest_marker("trustchain_verify")

        outcome = yield

        if marker and outcome.excinfo is None:
            # Get test result if it's a SignedResponse
            result = getattr(item, "_trustchain_result", None)
            if isinstance(result, SignedResponse):
                if not self.tc._signer.verify(result):
                    if self.config.getoption("trustchain_strict"):
                        pytest.fail("SignedResponse verification failed")

    def pytest_sessionfinish(self, session):
        """Generate report at end of session."""
        report_path = self.config.getoption("trustchain_report")
        if report_path:
            self._generate_report(report_path)

    def _generate_report(self, path: str):
        """Generate HTML verification report."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>TrustChain Test Report</title>
    <style>
        body {{ font-family: system-ui; max-width: 900px; margin: 2rem auto; }}
        h1 {{ color: #1a202c; }}
        .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; }}
        .stat {{ background: #f7fafc; padding: 1rem; border-radius: 8px; }}
        .stat-value {{ font-size: 2rem; font-weight: bold; color: #2d3748; }}
        .stat-label {{ color: #718096; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 2rem; }}
        th, td {{ text-align: left; padding: 0.75rem; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #f7fafc; }}
        .verified {{ color: #38a169; }}
        .failed {{ color: #e53e3e; }}
    </style>
</head>
<body>
    <h1>TrustChain Test Report</h1>
    <div class="stats">
        <div class="stat">
            <div class="stat-value">{len(self.responses)}</div>
            <div class="stat-label">Signed Responses</div>
        </div>
        <div class="stat">
            <div class="stat-value">{len(self.test_results)}</div>
            <div class="stat-label">Tests Run</div>
        </div>
        <div class="stat">
            <div class="stat-value">{sum(1 for r in self.responses if self.tc._signer.verify(r))}</div>
            <div class="stat-label">Verified</div>
        </div>
    </div>
</body>
</html>"""
        with open(path, "w") as f:
            f.write(html)


def pytest_configure(config):
    """Register plugin and custom markers."""
    config.addinivalue_line(
        "markers", "trustchain_verify: mark test to auto-verify SignedResponse returns"
    )
    config.addinivalue_line(
        "markers", "trustchain_sign(tool_id): mark test to auto-sign the return value"
    )
    config.pluginmanager.register(TrustChainPlugin(config), "trustchain")


# Re-export fixtures for pytest discovery (imported at top)
__all__ = ["tc", "async_tc", "signed_chain", "SignedChainCollector", "TrustChainPlugin"]
