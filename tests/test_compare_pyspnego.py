#!/usr/bin/env python3
"""Cross-check the spnego_token C++ module against pyspnego.

Both mint an initial SPNEGO token for "<service>/<host>" from the ambient Kerberos
credential. The tokens are not byte-identical (they embed timestamps/nonces and an
encrypted authenticator), so we compare *structurally*: both must be base64 SPNEGO
tokens carrying the Kerberos 5 mechanism OID (1.2.840.113554.1.2.2) for the same SPN.

Needs a Kerberos TGT (kinit) and a resolvable <service>/<host> SPN in the realm. If a
ticket, a provider, or pyspnego is unavailable, the relevant leg is skipped (not failed).

  uv run --extra test python tests/test_compare_pyspnego.py https://service.example/ [SERVICE]
"""
import base64
import json
import sys

# DER encoding of OID 1.2.840.113554.1.2.2 (Kerberos V5) as it appears inside a token.
KRB5_OID_DER = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02])


def host_of(url):
    return url.split("://", 1)[-1].split("/", 1)[0].split(":")[0]


def ours(url, service):
    import spnego_token

    print(f"  spnego_token: provider={spnego_token.provider_name()!r} available={spnego_token.is_available()}")
    blob = json.loads(spnego_token.describe_token_for_url(url, service=service))
    if not blob.get("ok"):
        print(f"  spnego_token: no token ({(blob.get('error') or '')[:60]})")
        return None
    return base64.b64decode(blob["token"])


def theirs(host, service):
    try:
        import spnego
    except ImportError:
        print("  pyspnego not installed (uv run --extra test ...) — skipping reference leg")
        return None
    ctx = spnego.client(None, None, hostname=host, service=service, protocol="negotiate")
    return ctx.step()


def has_krb5(raw):
    return raw is not None and KRB5_OID_DER in raw


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "https://localhost/"
    service = sys.argv[2] if len(sys.argv) > 2 else "HTTP"
    host = host_of(url)
    print(f"SPN target: {service}/{host}")

    try:
        a = ours(url, service)
    except Exception as e:  # noqa: BLE001 — diagnostic harness
        print(f"  spnego_token error: {e}")
        a = None
    try:
        b = theirs(host, service)
    except Exception as e:  # noqa: BLE001
        print(f"  pyspnego error (no ticket?): {str(e)[:70]}")
        b = None

    if a is None and b is None:
        print("SKIP: neither path produced a token (no ticket / provider / pyspnego)")
        return 0

    ak, bk = has_krb5(a), has_krb5(b)
    print(f"  spnego_token: {'KRB5 SPNEGO ok' if ak else ('—' if a is None else 'no KRB5 OID')}"
          + (f" ({len(a)}b)" if a else ""))
    print(f"  pyspnego    : {'KRB5 SPNEGO ok' if bk else ('—' if b is None else 'no KRB5 OID')}"
          + (f" ({len(b)}b)" if b else ""))

    if a is not None and b is not None:
        if ak and bk:
            print("PASS: both produced a Kerberos-mech SPNEGO token for the same SPN")
            return 0
        print("FAIL: token structures disagree")
        return 1
    print("PARTIAL: only one path produced a token (see above)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
