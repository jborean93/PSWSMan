# Copyright: (c) 2026, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""Authentication acceptor driven by the PSWSMan.Authentication.Tests project.

The tests spawn this script and talk to it over stdin/stdout, one JSON object
per line. It hosts a single pyspnego acceptor context so the module's client
side authentication and message protection can be verified against an
independent implementation without any HTTP or WSMan involved.

Every request is ``{"op": "...", ...}`` and every response is either
``{"ok": true, ...}`` or ``{"ok": false, "type": "<exception>", "error": "..."}``.
Binary values are base64 strings.

Operations:

``create``
    protocol, hostname, service, options (list of NegotiateOptions names),
    context_req (int, optional), channel_bindings (base64 application data,
    optional), tls (optional, CredSSP only: ``tls1.3``, ``tls1.2-aead`` or
    ``tls1.2-cbc`` pins the acceptor's TLS version and cipher family).
    Creates the acceptor context.
``step``
    token (base64 or null). Returns token (base64 or null) and complete.
``wrap`` / ``unwrap``
    data. Returns data and encrypted.
``wrap_winrm``
    data. Returns header, data and padding_length.
``unwrap_winrm``
    header, data. Returns data.
``query``
    Returns complete, negotiated_protocol, context_attr and client_principal.
    A CredSSP acceptor adds tls_protocol and tls_cipher once the handshake is
    done and delegated_credentials once it has received them.
``exit``
    Ends the process.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import ssl
import sys
import tempfile
import typing as t

import spnego
import spnego._ntlm
import spnego.tls
from spnego._ntlm_raw.messages import Challenge, NegotiateFlags, Version
from spnego.channel_bindings import GssChannelBindings


class _ChallengeWithVersion(Challenge):
    """Works around pyspnego <= 0.12.2 building a CHALLENGE without a Version field.

    The NTLM acceptor copies the initiator's flags into the CHALLENGE message,
    including NTLMSSP_NEGOTIATE_VERSION, but only writes the 8 byte Version
    structure when one is explicitly supplied. Strict decoders like gssntlmssp
    place the payload after that structure when the flag is set so every field
    offset then points 8 bytes too early and the message is rejected. Supplying
    a version whenever the flag is set produces the layout Windows sends.
    """

    def __init__(self, flags: int = 0, *args: t.Any, **kwargs: t.Any) -> None:
        if flags & NegotiateFlags.version and not kwargs.get("version"):
            kwargs["version"] = Version(major=10, minor=0, build=0, revision=0x0F)
        super().__init__(flags, *args, **kwargs)


spnego._ntlm.Challenge = _ChallengeWithVersion  # type: ignore[misc]


def b64(value: bytes | None) -> str | None:
    return base64.b64encode(value).decode() if value is not None else None


def unb64(value: str | None) -> bytes | None:
    return base64.b64decode(value) if value is not None else None


# The cipher lists are TLS 1.2 only, TLS 1.3 suites are all AEAD and cannot be restricted this way.
_TLS_VARIANTS: dict[str, tuple[ssl.TLSVersion, str | None]] = {
    "tls1.3": (ssl.TLSVersion.TLSv1_3, None),
    "tls1.2-aead": (ssl.TLSVersion.TLSv1_2, "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"),
    "tls1.2-cbc": (ssl.TLSVersion.TLSv1_2, "ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384"),
}


def create_tls_context(variant: str) -> spnego.tls.CredSSPTLSContext:
    """Builds a CredSSP acceptor TLS context pinned to one TLS version and cipher family.

    Mirrors what pyspnego does for its default acceptor context, a generated
    certificate loaded into default_tls_context, with the version and ciphers
    restricted on top.
    """
    version, ciphers = _TLS_VARIANTS[variant]

    ctx = spnego.tls.default_tls_context(usage="accept")
    cert_pem, key_pem, public_key = spnego.tls.generate_tls_certificate()

    # load_cert_chain opens the file itself which fails on Windows for a NamedTemporaryFile, use a directory.
    temp_dir = tempfile.mkdtemp()
    try:
        cert_path = os.path.join(temp_dir, "cert.pem")
        with open(cert_path, mode="wb") as fd:
            fd.write(cert_pem)
            fd.write(key_pem)
        ctx.context.load_cert_chain(cert_path)
    finally:
        shutil.rmtree(temp_dir)

    ctx.public_key = public_key
    ctx.context.minimum_version = version
    ctx.context.maximum_version = version
    if ciphers:
        ctx.context.set_ciphers(ciphers)

    return ctx


class Acceptor:
    def __init__(self) -> None:
        self.context: spnego.ContextProxy | None = None

    def _require_context(self) -> spnego.ContextProxy:
        if self.context is None:
            raise RuntimeError("The context has not been created")
        return self.context

    def op_create(self, request: dict[str, t.Any]) -> dict[str, t.Any]:
        options = spnego.NegotiateOptions.none
        for name in request.get("options") or []:
            options |= spnego.NegotiateOptions[name]

        bindings = None
        app_data = unb64(request.get("channel_bindings"))
        if app_data is not None:
            bindings = GssChannelBindings(application_data=app_data)

        kwargs: dict[str, t.Any] = {}
        if request.get("context_req") is not None:
            kwargs["context_req"] = spnego.ContextReq(request["context_req"])
        if request.get("tls") is not None:
            kwargs["credssp_tls_context"] = create_tls_context(request["tls"])

        self.context = spnego.server(
            hostname=request.get("hostname", "unspecified"),
            service=request.get("service", "host"),
            channel_bindings=bindings,
            protocol=request.get("protocol", "negotiate"),
            options=options,
            **kwargs,
        )
        return {}

    def op_step(self, request: dict[str, t.Any]) -> dict[str, t.Any]:
        context = self._require_context()
        out_token = context.step(unb64(request.get("token")))
        return {"token": b64(out_token), "complete": context.complete}

    def op_wrap(self, request: dict[str, t.Any]) -> dict[str, t.Any]:
        context = self._require_context()
        result = context.wrap(unb64(request["data"]) or b"", encrypt=request.get("encrypt", True))
        return {"data": b64(result.data), "encrypted": result.encrypted}

    def op_unwrap(self, request: dict[str, t.Any]) -> dict[str, t.Any]:
        context = self._require_context()
        result = context.unwrap(unb64(request["data"]) or b"")
        return {"data": b64(result.data), "encrypted": result.encrypted}

    def op_wrap_winrm(self, request: dict[str, t.Any]) -> dict[str, t.Any]:
        context = self._require_context()
        result = context.wrap_winrm(unb64(request["data"]) or b"")
        return {"header": b64(result.header), "data": b64(result.data), "padding_length": result.padding_length}

    def op_unwrap_winrm(self, request: dict[str, t.Any]) -> dict[str, t.Any]:
        context = self._require_context()
        data = context.unwrap_winrm(unb64(request["header"]) or b"", unb64(request["data"]) or b"")
        return {"data": b64(data)}

    def op_query(self, request: dict[str, t.Any]) -> dict[str, t.Any]:
        context = self._require_context()
        info: dict[str, t.Any] = {
            "complete": context.complete,
            "negotiated_protocol": context.negotiated_protocol,
            "context_attr": int(context.context_attr),
            "client_principal": context.client_principal,
        }

        # Both are CredSSP only, the TLS details are known once the handshake has finished.
        ssl_object = context.get_extra_info("ssl_object")
        cipher = ssl_object.cipher() if ssl_object is not None else None
        if cipher is not None:
            info["tls_cipher"], info["tls_protocol"], _ = cipher

        # Only a completed CredSSP acceptor returns this, the tests only delegate password credentials.
        password_creds = context.get_extra_info("client_credential")
        if password_creds is not None:
            info["delegated_credentials"] = {
                "domain": password_creds.domain_name,
                "username": password_creds.username,
                "password": password_creds.password,
            }

        return info

    def handle(self, request: dict[str, t.Any]) -> dict[str, t.Any]:
        op = request.get("op")
        handler = getattr(self, f"op_{op}", None) if isinstance(op, str) else None
        if handler is None:
            raise ValueError(f"Unknown operation '{op}'")

        return handler(request)


def main() -> None:
    acceptor = Acceptor()
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    while True:
        line = stdin.readline()
        if not line:
            break

        request = json.loads(line)
        if request.get("op") == "exit":
            break

        try:
            response = acceptor.handle(request)
            response["ok"] = True
        except Exception as e:  # noqa: BLE001 - every failure is reported to the test
            response = {"ok": False, "type": type(e).__name__, "error": str(e)}

        stdout.write(json.dumps(response).encode() + b"\n")
        stdout.flush()


if __name__ == "__main__":
    main()
