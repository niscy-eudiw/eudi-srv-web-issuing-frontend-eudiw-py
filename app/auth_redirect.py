"""Pushed authorization request proxy.

Wallets send the PAR to the credential issuer (this frontend); it is relayed
to the authorization server with the frontend id added, and with the wallet's
address in ``X-Forwarded-For`` so the authorization server can rate-limit per
wallet (with ``trusted_proxies: 1``). The request size is capped by
``MAX_CONTENT_LENGTH`` (``max_content_length``).
"""

import logging

import requests
from flask import Blueprint, Response, jsonify, request
from werkzeug.exceptions import HTTPException

from app import CONFIGURATION

authorization_endpoint = Blueprint("authorization_endpoint", __name__, url_prefix="/")

logger = logging.getLogger(__name__)

#: Wallet headers the authorization server needs (sender constraint, client attestation).
FORWARDED_REQUEST_HEADERS = ("DPoP", "OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP")
#: Upstream response headers relayed to the wallet; hop-by-hop and framing
#: headers (Transfer-Encoding, Content-Encoding, Connection, ...) are dropped.
RELAYED_RESPONSE_HEADERS = ("Content-Type", "Cache-Control", "Pragma", "DPoP-Nonce", "WWW-Authenticate")


@authorization_endpoint.route("/pushed_authorization", methods=["POST"])
def pushed_authorization():
    try:
        if request.content_type and "application/json" in request.content_type:
            body = request.get_json()
        else:
            body = request.form.to_dict()

        body["frontend_id"] = CONFIGURATION["frontend_id"]

        forward_headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Accept": "application/json",
            "Accept-Charset": "UTF-8",
            "User-Agent": request.headers.get("User-Agent", "proxy-service"),
            # The peer address only: a wallet-supplied X-Forwarded-For is not relayed.
            "X-Forwarded-For": request.remote_addr,
        }
        for header_name in FORWARDED_REQUEST_HEADERS:
            value = request.headers.get(header_name)
            if value is not None:
                forward_headers[header_name] = value

        # No wallet-supplied value in the log (log injection); the authorization
        # server logs the client after authenticating it.
        logger.info("Relaying pushed authorization request")
        response = requests.post(
            f"{CONFIGURATION['oauth_url']}/pushed_authorization",
            data=body,
            headers=forward_headers,
            timeout=30,
        )

        headers = [(name, response.headers[name]) for name in RELAYED_RESPONSE_HEADERS if name in response.headers]
        return Response(response.content, status=response.status_code, headers=headers)

    except HTTPException:
        # e.g. 413 from MAX_CONTENT_LENGTH while reading the body.
        raise
    except requests.exceptions.RequestException:
        logger.exception("Pushed authorization request relay failed")
        return _error({"error": "temporarily_unavailable", "error_description": "Authorization server unreachable"}, 502)
    except Exception:
        logger.exception("Pushed authorization request relay error")
        return _error({"error": "server_error"}, 500)


def _error(body: dict, status: int) -> Response:
    """A JSON error response (every return of the relay is a Response)."""
    response = jsonify(body)
    response.status_code = status
    return response
