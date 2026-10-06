"""Pushed authorization request proxy.

Wallets send the PAR to the credential issuer (this frontend); it is relayed
to the authorization server with the frontend id added.
"""

import logging

import requests
from flask import Blueprint, jsonify, request

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
        }
        for header_name in FORWARDED_REQUEST_HEADERS:
            if header_name in request.headers:
                forward_headers[header_name] = request.headers[header_name]

        logger.info(f"Relaying pushed authorization request for client {body.get('client_id')!r}")
        response = requests.post(
            f"{CONFIGURATION['oauth_url']}/pushed_authorization",
            data=body,
            headers=forward_headers,
            timeout=30,
        )

        headers = [(name, response.headers[name]) for name in RELAYED_RESPONSE_HEADERS if name in response.headers]
        return response.content, response.status_code, headers

    except requests.exceptions.RequestException:
        logger.exception("Pushed authorization request relay failed")
        return jsonify({"error": "temporarily_unavailable", "error_description": "Authorization server unreachable"}), 502
    except Exception:
        logger.exception("Pushed authorization request relay error")
        return jsonify({"error": "server_error"}), 500
