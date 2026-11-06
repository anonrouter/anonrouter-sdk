import anonrouter
import anonrouter_confidential
from anonrouter_confidential.gateway import dcap


def test_exports_are_the_confidential_package_objects():
    assert anonrouter.create_client is anonrouter_confidential.create_client
    assert anonrouter.verify_content_node is anonrouter_confidential.verify_content_node
    assert anonrouter.at_least is anonrouter_confidential.at_least
    assert anonrouter.ConfidentialClient is anonrouter_confidential.ConfidentialClient
    assert anonrouter.ConfidentialError is anonrouter_confidential.ConfidentialError
    assert anonrouter.create_anonrouter_dcap_verifier is dcap.create_anonrouter_dcap_verifier


def test_all_names_resolve():
    for name in anonrouter.__all__:
        assert hasattr(anonrouter, name), name
