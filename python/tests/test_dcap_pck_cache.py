"""Extraction/cache and request binding only; no synthetic hardware acceptance."""
import hashlib
import json
from pathlib import Path

import pytest

from anonrouter_confidential.gateway.dcap import engine
from anonrouter_confidential.gateway.dcap.collateral import (
    AcquiredCollateral,
    CollateralCache,
    CollateralError,
    DcapCollateral,
)
from anonrouter_confidential.gateway.dcap.engine import (
    AnonRouterDcapVerifier,
    DcapEngineVerdictV1,
)

FIXTURE = json.loads((Path(__file__).resolve().parents[2] / 'shared/vectors/dcap-same-fmspc-pck-chains.json').read_text())
for chain in FIXTURE['chains']:
    assert hashlib.sha256(chain['pem'].encode()).hexdigest() == chain['sha256']
CARRIERS = [('extraction-only\0' + chain['pem'] + '\0').encode('latin1').hex() for chain in FIXTURE['chains']]
PLATFORM = {'pck_crl_issuer_chain': 'issuer', 'root_ca_crl': '00', 'pck_crl': '01', 'tcb_info_issuer_chain': 'tcb issuer', 'tcb_info': 'exact signed bytes', 'tcb_info_signature': '02', 'qe_identity_issuer_chain': 'qe issuer', 'qe_identity': 'exact qe bytes', 'qe_identity_signature': '03'}
CACHED = AcquiredCollateral(DcapCollateral(**PLATFORM, pck_certificate_chain=FIXTURE['chains'][0]['pem']), FIXTURE['fmspc'], 1000, 1)
def test_distinct_pcks_share_platform_fetch_without_mutation():
    calls = []
    cache = CollateralCache(lambda quote: (calls.append(quote), CACHED)[1])
    first, second = cache.get(CARRIERS[0], 10), cache.get(CARRIERS[1], 10)
    assert len(calls) == 1
    assert first.collateral.pck_certificate_chain == FIXTURE['chains'][0]['pem']
    assert second.collateral.pck_certificate_chain == FIXTURE['chains'][1]['pem']
    assert first.collateral is not second.collateral
    assert CACHED.collateral.pck_certificate_chain == FIXTURE['chains'][0]['pem']
    assert cache.peek(FIXTURE['fmspc']).collateral.as_dict() == PLATFORM
    assert cache.get(CARRIERS[0], 10) == first

def test_cross_platform_refuses_before_cache_write():
    wrong = AcquiredCollateral(CACHED.collateral, '20a06f000000', 1000, 1)
    cache = CollateralCache(lambda _: wrong)
    with pytest.raises(CollateralError, match='platform'):
        cache.get(CARRIERS[1], 10)
    assert cache.peek(wrong.fmspc) is None

def test_native_adapter_omits_other_host_override_for_each_quote(monkeypatch):
    captured = []
    def capture(_, request, __):
        captured.append(request)
        return DcapEngineVerdictV1(False, None, None, None, [], None, 'synthetic carrier; no acceptance', 'wire-capture')
    monkeypatch.setattr(engine, 'run_dcap_engine', capture)
    verifier = AnonRouterDcapVerifier(binary_path='/usr/bin/true', collateral=CACHED.collateral, fetch_collateral=False)
    for quote in CARRIERS:
        prepared = verifier.prepare(quote, now_ms=10)
        assert prepared.verify_chain(quote)[0] is False
        assert captured[-1]['quote'] == quote
        assert captured[-1]['collateral'] == PLATFORM
    assert CACHED.collateral.pck_certificate_chain == FIXTURE['chains'][0]['pem']
