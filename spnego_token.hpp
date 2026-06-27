#pragma once

#include <string>

namespace spnego {

//! Result of a SPNEGO token generation attempt.
struct TokenResult {
	std::string token;    // base64-encoded SPNEGO token
	std::string url;      // the original URL (empty for the host+service primitive)
	std::string hostname; // host the SPN was built from
	std::string spn;      // constructed SPN: "<service>/<host>" (SSPI) or "<service>@<host>" (GSS)
	std::string provider; // "SSPI" | "GSS-API" | "GSS-API (GSS.framework)" | "unavailable"
	std::string library;  // path/name of the loaded security library (Unix)
};

//! Primitive: mint a pre-flight SPNEGO token for the SPN "<service>/<host>" from the
//! ambient Kerberos credential, via GSS-API (macOS/Linux) or SSPI (Windows).
//! `service` is the SPN service class — "HTTP" (default), "LDAP", "cifs", "host", … —
//! so this is NOT HTTP-specific. No URL, no transport guard; the returned url is empty.
//! Throws std::runtime_error if no provider is available or token generation fails.
TokenResult GenerateTokenForHost(const std::string &host, const std::string &service = "HTTP");

//! HTTP/URL convenience: extract the host from `url` (gating plaintext http:// unless
//! allow_insecure — e.g. over a Tailscale/WireGuard overlay), then GenerateTokenForHost.
//! `service` defaults to "HTTP". Sets TokenResult.url to the given url.
TokenResult GenerateTokenForUrl(const std::string &url, bool allow_insecure = false,
                                const std::string &service = "HTTP");

//! Debug entry-point: like GenerateTokenForUrl but never throws. Returns a pretty JSON
//! string echoing the inputs, the targeted service name (SPN), provider/library, and the
//! token — or, on failure, an "error" with the SPN still reported. For diagnosing
//! SPN / DNS-canonicalization / missing-ticket issues. (Uses nlohmann::json.)
std::string DescribeTokenForUrl(const std::string &url, bool allow_insecure = false,
                                const std::string &service = "HTTP");

//! True if a security provider (GSS-API or SSPI) is available on this system.
bool IsAvailable();

//! Name/path of the loaded security library, or empty if none.
std::string LibraryName();

//! Provider name ("SSPI", "GSS-API", "GSS-API (GSS.framework)", or "unavailable").
std::string ProviderName();

} // namespace spnego
