from trustchain.integrations.onaidocs import OnaiDocsTrustClient


def test_onaidocs_client_create():
    client = OnaiDocsTrustClient("http://localhost:9323")
    assert client.base_url == "http://localhost:9323"
