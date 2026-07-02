"""Hugin Agent wire-protocol v1.0.0 — Python reference verifier (auth surface).

A line-by-line port of the FROZEN TypeScript contract code, for a non-TS relay
(C2). Sources of truth (byte-identical semantics required):

  - transcript.ts  -> lp(), build_transcript()          (auth-pairing-spec §5)
  - origin.ts      -> canonicalize_server_origin(), validate_tenant_id()
  - ed25519.ts     -> verify_transcript()  (strict: canonical S, 64-byte sig)
  - messages.ts    -> AUTH_ID / SemVer / nonce field grammars (auth fields only)

Conformance is proven against protocol/v1/test-vectors.json by selftest.py —
run it in the relay's CI. The vectors' Ed25519 seed is a fixed, PUBLIC test
constant (implementation grading only); a production relay must never register
its public key (see REJECTED_TEST_PUBLIC_HEX).

Requires: cryptography >= 42 (Ed25519 via OpenSSL — strict verification:
non-canonical S and low-order/identity public keys are rejected).

Scope: the auth/handshake surface only. The full 23-message wire schema
(messages.ts) still needs a pydantic port for the job-lifecycle layer.
"""

from __future__ import annotations

import base64
import re
import struct
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROTOCOL_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# transcript.ts — canonical signing bytes (auth-pairing-spec §5)
# ---------------------------------------------------------------------------

DOMAIN_TAG = "hugin-agent/auth/v1"
ALG = "ed25519"


def lp(x: str | bytes) -> bytes:
    """Length-prefix: uint32_be(byte_length(x)) || x. Strings are UTF-8."""
    body = x if isinstance(x, bytes) else x.encode("utf-8")
    return struct.pack(">I", len(body)) + body


def build_transcript(
    *,
    challenge_id: str,
    nonce_raw: bytes,
    agent_id: str,
    key_id: str,
    protocol_version: str,
    tenant_id: str,
    server_origin: str,
) -> bytes:
    """Canonical transcript. `nonce_raw` is the raw 32 bytes, NO length prefix;
    every other field is lp()'d. Field order is FROZEN."""
    if len(nonce_raw) != 32:
        raise ValueError(f"nonce_raw must be 32 bytes, got {len(nonce_raw)}")
    return b"".join(
        [
            lp(DOMAIN_TAG),
            lp(challenge_id),
            nonce_raw,  # RAW 32 bytes, NO length prefix
            lp(agent_id),
            lp(key_id),
            lp(protocol_version),
            lp(ALG),
            lp(tenant_id),
            lp(server_origin),
        ]
    )


# ---------------------------------------------------------------------------
# messages.ts — auth field grammars (parse-level gates, run BEFORE crypto)
# ---------------------------------------------------------------------------

# AuthId: ids that enter the signed transcript (challenge_id, agent_id, key_id).
# ASCII-only — defeats UTF-16-vs-byte signature mismatches (Codex B).
AUTH_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")

# SemVer core + optional prerelease, <=64; `+build` intentionally rejected.
SEMVER_RE = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?")

NONCE_RE = re.compile(r"[A-Za-z0-9_-]{43}")  # unpadded base64url, exactly 43


def validate_auth_id(v: str) -> bool:
    return AUTH_ID_RE.fullmatch(v) is not None


def validate_protocol_version(v: str) -> bool:
    return len(v) <= 64 and SEMVER_RE.fullmatch(v) is not None


def decode_nonce(nonce_b64u: str) -> bytes | None:
    """Decode the 43-char unpadded-base64url challenge nonce to its raw 32
    bytes. Returns None for wrong length/charset/padding — and for canonical-
    encoding violations (the 2 leftover pad bits must be zero), so two distinct
    strings can never alias one transcript."""
    if not NONCE_RE.fullmatch(nonce_b64u):
        return None
    raw = base64.urlsafe_b64decode(nonce_b64u + "=")
    if len(raw) != 32:
        return None
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != nonce_b64u:
        return None  # non-canonical pad bits
    return raw


# ---------------------------------------------------------------------------
# origin.ts — server_origin canonical form + tenant_id grammar
# ---------------------------------------------------------------------------

TENANT_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")

_DNS_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_LOOPBACK_V4_RE = re.compile(r"127(?:\.\d{1,3}){3}")
_DEFAULT_PORT = {"wss": 443, "ws": 80}


def validate_tenant_id(t: str) -> bool:
    return TENANT_ID_RE.fullmatch(t) is not None


def canonicalize_server_origin(inp: str) -> str | None:
    """Returns the canonical server_origin, or None if non-canonical/invalid.
    A verifier REJECTS non-canonical input — it never silently normalizes.

    Porting note vs origin.ts: the TS side leans on the WHATWG URL parser
    (lowercases the host, punycodes IDN, drops scheme-default ports) and then
    rejects on `canonical != input`. Python's urlsplit does none of that
    normalization, so the same behaviors are enforced with explicit checks:
    non-ASCII host -> reject (canonical form is ASCII punycode), explicit
    default port -> reject. Outcomes are identical: only an already-canonical
    string is accepted."""
    try:
        u = urlsplit(inp)
        port = u.port  # raises ValueError on a malformed/out-of-range port
    except ValueError:
        return None

    scheme = u.scheme
    if scheme not in ("wss", "ws"):
        return None
    host = u.hostname  # lowercased; IPv6 comes back WITHOUT brackets
    if not host:
        return None
    if not host.isascii():
        return None  # raw IDN is non-canonical (must be punycoded already)

    is_ipv6 = ":" in host
    display_host = f"[{host}]" if is_ipv6 else host
    is_loopback = (
        display_host in ("localhost", "[::1]")
        or _LOOPBACK_V4_RE.fullmatch(host) is not None
    )

    if scheme == "ws" and not is_loopback:
        return None  # ws:// is loopback-dev only
    if u.username or u.password:
        return None
    if u.query or u.fragment:
        return None
    if u.path and u.path != "/":
        return None
    if port == 0:
        return None
    if host.endswith("."):
        return None
    if "%" in host:
        return None

    is_ipv4 = _IPV4_RE.fullmatch(host) is not None
    if (is_ipv6 or is_ipv4) and not is_loopback:
        return None  # production = DNS-only
    if not is_loopback:
        if not all(_DNS_LABEL_RE.fullmatch(label) for label in host.split(".")):
            return None
    if port == _DEFAULT_PORT[scheme]:
        return None  # explicit default port is non-canonical

    port_part = f":{port}" if port is not None else ""
    canonical = f"{scheme}://{display_host}{port_part}"
    if canonical != inp:
        return None  # input must already be canonical
    return canonical


# ---------------------------------------------------------------------------
# ed25519.ts — strict signature verification
# ---------------------------------------------------------------------------

_SIG_RE = re.compile(r"[A-Za-z0-9_-]{86}")  # 64 bytes as unpadded base64url
# Ed25519 group order L (RFC 8032). S >= L is a malleable, non-canonical
# signature; checked explicitly so strictness never depends on the backend.
_ED25519_L = 2**252 + 27742317777372353535851937790883648493

# The PUBLIC test key from test-vectors.json (seed 0102..1f20). A production
# pairing endpoint MUST refuse to register it — anyone with the repo can sign
# for it.
REJECTED_TEST_PUBLIC_HEX = (
    "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def verify_transcript(public_raw: bytes, transcript: bytes, signature_b64u: str) -> bool:
    """Verify an unpadded-base64url Ed25519 signature over `transcript` against
    a raw 32-byte registered public key. Returns False on ANY failure — never
    raises — so a malformed signature is a clean `bad_signature`, not a crash."""
    if len(public_raw) != 32:
        return False
    if not _SIG_RE.fullmatch(signature_b64u):
        return False
    try:
        sig = base64.urlsafe_b64decode(signature_b64u + "==")
        if len(sig) != 64:
            return False
        if int.from_bytes(sig[32:], "little") >= _ED25519_L:
            return False  # non-canonical S
        pub = Ed25519PublicKey.from_public_bytes(public_raw)
        pub.verify(sig, transcript)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


def sign_transcript_for_test(seed: bytes, transcript: bytes) -> str:
    """Deterministic Ed25519 signing from a raw 32-byte seed — TEST/VECTOR use
    only. In production the private key lives in the DEVICE's OS keychain; the
    relay never holds or uses a private key."""
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return b64u(priv.sign(transcript))


# ---------------------------------------------------------------------------
# pairing.ts — pairing PoP transcript (Pairing Ceremony rev2 §8; off-wire)
# ---------------------------------------------------------------------------

PAIRING_DOMAIN_TAG = "hugin-pair-pop-v1"

# 43-char unpadded base64url — the pairing secret / public_key / fingerprint grammar.
PAIRING_SECRET_RE = re.compile(r"[A-Za-z0-9_-]{43}")


def validate_b64u32(s: str) -> bool:
    """Canonical 43-char unpadded base64url encoding exactly 32 bytes: charset,
    length, AND zero trailing pad bits (decode → re-encode must round-trip).
    Gate for the pairing `secret` and POST-body `public_key` — C2 rejects
    non-canonical aliases BEFORE any crypto, because `sha256(secret)` is
    defined over the exact UTF-8 string."""
    if not PAIRING_SECRET_RE.fullmatch(s):
        return False
    raw = base64.urlsafe_b64decode(s + "=")
    return len(raw) == 32 and b64u(raw) == s


def build_pairing_transcript(
    *,
    secret: str,
    public_raw: bytes,
    server_origin: str,
    protocol_version: str,
) -> bytes:
    """Canonical pairing-PoP signing bytes (ceremony rev2 §8). `secret` is the
    43-char base64url STRING signed as UTF-8 text (never hashed or decoded);
    `public_raw` is the raw 32-byte key WITHOUT a length prefix. The domain tag
    is distinct from the handshake tag, so a pairing PoP can never replay as a
    handshake signature (or vice versa)."""
    if not validate_b64u32(secret):
        raise ValueError("pairing secret must be 43 canonical unpadded base64url chars (32 bytes)")
    if len(public_raw) != 32:
        raise ValueError(f"public key must be 32 raw bytes, got {len(public_raw)}")
    return b"".join(
        [
            lp(PAIRING_DOMAIN_TAG),
            lp(secret),
            public_raw,  # RAW 32 bytes, NO length prefix
            lp(server_origin),
            lp(protocol_version),
        ]
    )


def key_fingerprint(public_raw: bytes) -> str:
    """Device-key fingerprint (rev2 M2): full unpadded base64url(SHA-256(raw32
    public key)) — 43 chars, NO truncation. Must render byte-identical on the
    daemon CLI and the C2 browser confirm screen (grouping is display-only)."""
    import hashlib

    if len(public_raw) != 32:
        raise ValueError(f"public key must be 32 raw bytes, got {len(public_raw)}")
    return b64u(hashlib.sha256(public_raw).digest())
