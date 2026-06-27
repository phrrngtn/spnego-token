// nanobind wrapper around the spnego-token C++ atom, so the same code that ships in
// blobsso (and other consumers) can be exercised from Python and cross-checked against
// pyspnego. This binding adds nothing to the logic — it is a thin debug/test surface.

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>

#include "spnego_token.hpp"

namespace nb = nanobind;

NB_MODULE(spnego_token, m) {
	m.doc() = "Curl-free SPNEGO (RFC 4178/4559) token generator for preemptive auth";

	nb::class_<spnego::TokenResult>(m, "TokenResult")
	    .def_ro("token", &spnego::TokenResult::token, "base64-encoded SPNEGO token")
	    .def_ro("url", &spnego::TokenResult::url)
	    .def_ro("hostname", &spnego::TokenResult::hostname)
	    .def_ro("spn", &spnego::TokenResult::spn, "constructed SPN, e.g. HTTP/host or LDAP@host")
	    .def_ro("provider", &spnego::TokenResult::provider, "SSPI | GSS-API | GSS-API (GSS.framework)")
	    .def_ro("library", &spnego::TokenResult::library, "loaded security library (Unix)")
	    .def("__repr__", [](const spnego::TokenResult &r) {
		    return std::string("<TokenResult spn='") + r.spn + "' provider='" + r.provider +
		           "' token_len=" + std::to_string(r.token.size()) + ">";
	    });

	m.def("generate_token_for_host", &spnego::GenerateTokenForHost, nb::arg("host"), nb::arg("service") = "HTTP",
	      "Mint a base64 SPNEGO token for the SPN <service>/<host> from the ambient Kerberos credential. "
	      "service: HTTP (default), LDAP, cifs, host, … Raises on failure.");
	m.def("generate_token_for_url", &spnego::GenerateTokenForUrl, nb::arg("url"), nb::arg("allow_insecure") = false,
	      nb::arg("service") = "HTTP",
	      "Like generate_token_for_host, but takes a URL (host extracted; plaintext http:// gated "
	      "unless allow_insecure=True). Raises on failure.");
	m.def("describe_token_for_url", &spnego::DescribeTokenForUrl, nb::arg("url"), nb::arg("allow_insecure") = false,
	      nb::arg("service") = "HTTP",
	      "Debug: never raises. Returns a JSON string with the inputs, the targeted service name (SPN), "
	      "provider/library, and the token (or an error). Pair with json.loads().");
	m.def("is_available", &spnego::IsAvailable, "True if a security provider (GSS-API/SSPI) is loadable.");
	m.def("provider_name", &spnego::ProviderName, "Name of the active security provider.");
	m.def("library_name", &spnego::LibraryName, "Path/name of the loaded security library (Unix).");
}
