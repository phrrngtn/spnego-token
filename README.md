# spnego-token

> **Note:** This code is almost entirely AI-authored (Claude, Anthropic), albeit under close human supervision, and is for research and experimentation purposes. Successful experiments may be re-implemented in a more coordinated and curated manner.

A tiny, dependency-light C++ component that mints a **base64 SPNEGO token** (GSS-API,
[RFC 4178](https://www.rfc-editor.org/rfc/rfc4178) / [RFC 4559](https://www.rfc-editor.org/rfc/rfc4559))
from the ambient Kerberos credential — for **preemptive** authentication. Ships with a
[nanobind](https://github.com/wjakob/nanobind) Python module so the C/C++ can be exercised
and cross-checked against [`pyspnego`](https://github.com/jborean93/pyspnego).

## What "preemptive" means (and why it's the whole point)

Standard Negotiate is *challenge-response*: the client makes a request, the server replies
`401 WWW-Authenticate: Negotiate`, and only then does the client send the token — sometimes
over several legs for mutual auth. That round-trip is why clients that "do Kerberos" tend to
link a heavyweight stack (curl `--negotiate`, etc.) to manage the challenge, connection
affinity, and multi-leg GSS context.

**Preemptive** auth skips all of it: the client calls `gss_init_sec_context` **once** as the
initiator, produces a **single-leg** token, and attaches it to the *first* request. No 401,
no return-token loop, no connection pinning. This library does exactly one thing — **produce
that base64 string** — so *any* client that can set a field (an HTTP header, a SASL token, …)
can do Kerberos auth without a Negotiate-aware transport stack. That is what lets a caller be
**curl-free**.

> Not to be confused with **Kerberos pre-authentication** (the `PA-DATA` step between client
> and KDC during AS-REQ). This is *preemptive* auth — asserting an already-obtained credential
> on the first request.

## Not HTTP-only

SPNEGO is a GSS-API mechanism, not an HTTP thing — the same token is used by **HTTP**
(`Authorization: Negotiate`), **LDAP** (SASL GSS-SPNEGO), **SMB/CIFS**, **MS-RPC**, **WinRM**,
SASL mail, etc. The base64 is just transport sugar for text protocols; binary protocols use the
raw bytes. So the SPN **service class** is a parameter (`service`, default `"HTTP"`):

```cpp
#include "spnego_token.hpp"

// HTTP (default): SPN HTTP/host
spnego::TokenResult r = spnego::GenerateTokenForUrl("https://service.example/");
// -> r.token   (base64 SPNEGO token; e.g. Authorization: Negotiate <r.token>)
//    r.spn = "HTTP@service.example", r.provider = "GSS-API (GSS.framework)"

// Any Kerberos service, by host + class (no URL):
auto ldap = spnego::GenerateTokenForHost("dc.example", "LDAP");   // SPN LDAP/dc.example
auto smb  = spnego::GenerateTokenForHost("fs.example", "cifs");   // SPN cifs/fs.example
```

(A future `mechanism` arg could select raw-Kerberos vs SPNEGO, for LDAP `GSSAPI` binds; not
built yet.)

## C++ API

| Function | Purpose |
|---|---|
| `GenerateTokenForHost(host, service="HTTP")` | Primitive — SPN `<service>/<host>`, any Kerberos service. |
| `GenerateTokenForUrl(url, allow_insecure=false, service="HTTP")` | URL convenience — extracts host (gates plaintext `http://` unless `allow_insecure`). |
| `DescribeTokenForUrl(url, allow_insecure=false, service="HTTP")` | **Debug** — never throws; returns a JSON blob (inputs, SPN, provider, token-or-error). |
| `GenerateTokenFromConfig(json)` | Property-bag — strict JSON config `{"url"\|"host", "service", "allow_insecure"}`; unknown keys / ambiguous host raise. |
| `IsAvailable()` / `ProviderName()` / `LibraryName()` | Provider introspection. |

All return a `TokenResult { token, url, hostname, spn, provider, library }` (except the
`Describe` debug entry-point, which returns a JSON string via `nlohmann::json`).

## Platforms / dependencies

| Platform | Provider | Linkage |
|---|---|---|
| Linux | GSS-API (`libgssapi_krb5.so.2`) | **dlopen'd at runtime** — no link dep |
| macOS | GSS-API (`GSS.framework`) | dlopen'd at runtime |
| Windows | SSPI | link `secur32` |

No curl, no OpenSSL, no HTTP library. The OS Kerberos libraries are resolved at runtime. The
only build-time dependency is header-only **nlohmann/json** (a submodule), used by the
`Describe…` debug entry-point.

## Use as a git submodule (C++)

```sh
git submodule add --recursive https://github.com/phrrngtn/spnego-token.git third_party/spnego-token
```
In CMake: add `third_party/spnego-token` **and** `third_party/spnego-token/third_party/json/single_include`
to your includes, and compile `third_party/spnego-token/spnego_token.cpp` into your target. On
Windows, link `secur32`. That's the whole integration.

Consumed by [`blobsso`](https://github.com/phrrngtn/blobsso) (Kerberos → STS → auto-rotating S3
secret provider), and intended as the single shared source for the other blob* auth extensions.

## Python module (debug / cross-check vs pyspnego)

A nanobind wrapper builds the same C++ into an importable module:

```sh
uv build                 # or: uv pip install -e .
uv run python -c "import spnego_token; print(spnego_token.provider_name(), spnego_token.is_available())"

# Cross-check against pyspnego (needs a Kerberos ticket + a known SPN):
uv run --extra test python tests/test_compare_pyspnego.py https://service.example/
```

Exposes `generate_token_for_host(host, service="HTTP")`,
`generate_token_for_url(url, allow_insecure=False, service="HTTP")`,
`describe_token_for_url(...) -> json`, `generate_token_from_config(json)`, `is_available()`,
`provider_name()`, `library_name()`.

## Acknowledgments

The preemptive-SPNEGO approach — assert a single-leg Negotiate token on the first request
rather than waiting for a challenge — was explained to me by **Richard E. Silverman**, and was
prototyped against `pyspnego` before the C++ implementation.

## License

MIT — see [LICENSE](LICENSE).
