"""Conformance selftest for the Python reference verifier — mirrors the vector
section of protocol/v1/selftest.ts (same pass/fail semantics per failure_mode).

Run:  python3 protocol/v1/py/selftest.py
Exit: 0 = fully conformant with the frozen v1.0.0 contract; 1 = drift.

Positives assert MORE than the TS selftest: the transcript is byte-compared
against transcript_hex (so a builder bug is localized to a byte offset, not a
mystery signature failure), the deterministic signature must MATCH exactly,
and verification must succeed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from hugin_protocol_v1 import (  # noqa: E402
    ALG,
    DOMAIN_TAG,
    PAIRING_DOMAIN_TAG,
    build_pairing_transcript,
    build_transcript,
    canonicalize_server_origin,
    decode_nonce,
    key_fingerprint,
    lp,
    sign_transcript_for_test,
    validate_auth_id,
    validate_protocol_version,
    validate_tenant_id,
    verify_transcript,
)

VECTORS = json.loads((Path(__file__).parent.parent / "test-vectors.json").read_text())
PAIRING_VECTORS_PATH = Path(__file__).parent.parent / "pairing-test-vectors.json"

checks: list[tuple[str, bool]] = []


def check(label: str, ok: bool) -> None:
    checks.append((label, ok))


# --- positives -------------------------------------------------------------

check("domain_tag matches vectors", VECTORS["domain_tag"] == DOMAIN_TAG)
check("alg matches vectors", VECTORS["alg"] == ALG)

for v in VECTORS["positives"]:
    tag = f"vector+ {v['label']}"
    nonce_raw = decode_nonce(v["nonce_base64url"])
    check(f"{tag}: nonce decodes canonically", nonce_raw == bytes.fromhex(v["nonce_raw_hex"]))
    check(
        f"{tag}: origin canonicalizes",
        canonicalize_server_origin(v["input_server_origin"]) == v["canonical_server_origin"],
    )
    check(f"{tag}: ids/tenant/version pass grammars",
          validate_auth_id(v["challenge_id"]) and validate_auth_id(v["agent_id"])
          and validate_auth_id(v["key_id"]) and validate_tenant_id(v["tenant_id"])
          and validate_protocol_version(v["protocol_version"]))

    transcript = build_transcript(
        challenge_id=v["challenge_id"],
        nonce_raw=bytes.fromhex(v["nonce_raw_hex"]),
        agent_id=v["agent_id"],
        key_id=v["key_id"],
        protocol_version=v["protocol_version"],
        tenant_id=v["tenant_id"],
        server_origin=v["canonical_server_origin"],
    )
    check(f"{tag}: lp(domain_tag) bytes", lp(DOMAIN_TAG).hex() == v["domain_tag_hex"])
    check(f"{tag}: lp(alg) bytes", lp(ALG).hex() == v["alg_lp_hex"])
    check(f"{tag}: transcript bytes match", transcript.hex() == v["transcript_hex"])

    seed = bytes.fromhex(v["ed25519_seed_hex"])
    check(
        f"{tag}: deterministic signature matches",
        sign_transcript_for_test(seed, transcript) == v["expected_signature_base64url"],
    )
    check(
        f"{tag}: signature verifies",
        verify_transcript(
            bytes.fromhex(v["ed25519_public_hex"]), transcript, v["expected_signature_base64url"]
        ),
    )

# --- negatives (same routing as selftest.ts) --------------------------------

for v in VECTORS["negatives"]:
    tag = f"vector- {v['label']} ({v['failure_mode']}): rejected"
    if v["failure_mode"] == "parse":
        field = v["field"]
        if field == "nonce":
            ok = decode_nonce(v["value"]) is None
        elif field in ("agent_id", "key_id", "challenge_id"):
            ok = not validate_auth_id(v["value"])
        elif field == "protocol_version":
            ok = not validate_protocol_version(v["value"])
        else:
            ok = False  # unknown parse field — fail loudly
    elif v["failure_mode"] == "origin":
        ok = canonicalize_server_origin(v["input_server_origin"]) is None
    elif v["failure_mode"] == "tenant":
        ok = not validate_tenant_id(v["tenant_id"])
    elif v["failure_mode"] == "signature":
        transcript = build_transcript(
            challenge_id=v["challenge_id"],
            nonce_raw=bytes.fromhex(v["nonce_raw_hex"]),
            agent_id=v["agent_id"],
            key_id=v["key_id"],
            protocol_version=v["protocol_version"],
            tenant_id=v["tenant_id"],
            server_origin=v["canonical_server_origin"],
        )
        ok = not verify_transcript(
            bytes.fromhex(v["ed25519_public_hex"]),
            transcript,
            v["expected_signature_base64url"],
        )
    else:
        ok = False
    check(tag, ok)

# --- pairing PoP vectors (ceremony rev2 §8; skipped if file absent) ----------

if PAIRING_VECTORS_PATH.exists():
    import hashlib

    from hugin_protocol_v1 import REJECTED_TEST_PUBLIC_HEX, validate_b64u32

    PV = json.loads(PAIRING_VECTORS_PATH.read_text())
    check("pairing schema is 1", PV["schema"] == 1)
    check("pairing domain_tag matches", PV["domain_tag"] == PAIRING_DOMAIN_TAG)
    check("pairing rejected test key matches", PV["rejected_test_public_hex"] == REJECTED_TEST_PUBLIC_HEX)

    for v in PV["positives"]:
        tag = f"pairing+ {v['label']}"
        public_raw = bytes.fromhex(v["ed25519_public_hex"])
        transcript = build_pairing_transcript(
            secret=v["secret"],
            public_raw=public_raw,
            server_origin=v["canonical_server_origin"],
            protocol_version=v["protocol_version"],
        )
        check(f"{tag}: secret is canonical", validate_b64u32(v["secret"]))
        check(
            f"{tag}: origin is frozen-canonical",
            canonicalize_server_origin(v["canonical_server_origin"]) == v["canonical_server_origin"],
        )
        check(f"{tag}: transcript bytes match", transcript.hex() == v["transcript_hex"])
        check(
            f"{tag}: secret_sha256 is over the UTF-8 string",
            hashlib.sha256(v["secret"].encode("utf-8")).hexdigest() == v["secret_sha256_hex"],
        )
        check(
            f"{tag}: deterministic signature matches",
            sign_transcript_for_test(bytes.fromhex(v["ed25519_seed_hex"]), transcript)
            == v["expected_pop_signature_base64url"],
        )
        check(
            f"{tag}: signature verifies",
            verify_transcript(public_raw, transcript, v["expected_pop_signature_base64url"]),
        )
        check(f"{tag}: fingerprint matches", key_fingerprint(public_raw) == v["fingerprint_base64url"])

    for v in PV["negatives"]:
        tag = f"pairing- {v['label']} ({v['failure_mode']})"
        if v["failure_mode"] == "parse":
            check(f"{tag}: rejected at the input gate", not validate_b64u32(v["value"]))
        elif v["failure_mode"] == "signature":
            public_raw = bytes.fromhex(v["ed25519_public_hex"])
            transcript = build_pairing_transcript(
                secret=v["secret"],
                public_raw=public_raw,
                server_origin=v["canonical_server_origin"],
                protocol_version=v["protocol_version"],
            )
            check(f"{tag}: presented transcript rebuilds", transcript.hex() == v["transcript_hex"])
            check(
                f"{tag}: rejected",
                not verify_transcript(public_raw, transcript, v["expected_pop_signature_base64url"]),
            )
        elif v["failure_mode"] == "policy":
            check(
                f"{tag}: pins the published test key",
                v["ed25519_public_hex"] == REJECTED_TEST_PUBLIC_HEX,
            )
        else:
            check(f"{tag}: unknown failure_mode", False)
else:
    print("(pairing-test-vectors.json absent — pairing checks skipped)")

# --- report ------------------------------------------------------------------

failures = 0
for label, ok in checks:
    print(("✓" if ok else "✗"), label)
    if not ok:
        failures += 1

if failures:
    print(f"\n{failures} failure(s)", file=sys.stderr)
    sys.exit(1)
print(f"\nAll {len(checks)} checks passed — Python verifier conforms to v1.0.0.")
