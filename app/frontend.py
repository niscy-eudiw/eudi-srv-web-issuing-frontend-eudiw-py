"""Frontend pages.

The backend sends the data of most pages as a JSON ``payload`` form field
from an auto-submitting page. Anyone can post such a form, so every value is
treated as untrusted:

* URLs the page posts or navigates to must be on the backend
  (:func:`_backend_url`);
* wallet links must use a scheme that cannot run code (:func:`_wallet_url`);
* QR codes must be PNG data URIs (:func:`_qr_code`).

A value that fails these checks gets ``400``.
"""

import json
import logging
import re
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urlsplit

from flask import (
    Blueprint,
    abort,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
)

from app import oidc_metadata, openid_metadata, signed_metadata
from app import CONFIGURATION

frontend = Blueprint("frontend", __name__, url_prefix="/")

logger = logging.getLogger(__name__)

#: Wallet / offer link: ``scheme://...`` with no character that could leave
#: an HTML attribute or a URL.
_WALLET_URL = re.compile(r"[a-z][a-z0-9+.\-]{0,31}://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%\-]{0,8000}")
#: Schemes that run code or read local data when a link is opened.
_FORBIDDEN_SCHEMES = frozenset({"javascript", "data", "vbscript", "file", "blob", "about"})
_QR_PREFIX = "data:image/png;base64,"
_BASE64 = re.compile(r"[A-Za-z0-9+/=]*")


class InvalidPayload(ValueError):
    """Raised when a payload value fails validation."""


def _load_payload() -> Dict[str, Any]:
    """Reads the JSON ``payload`` form field.

    Returns:
        The decoded payload.

    Raises:
        InvalidPayload: If it is missing or not a JSON object.
    """
    raw = request.form.get("payload")
    if not raw:
        raise InvalidPayload("Payload not found")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        raise InvalidPayload("Invalid JSON payload") from e
    if not isinstance(payload, dict):
        raise InvalidPayload("Invalid JSON payload")
    return payload


def _backend_url(value: Optional[str]) -> str:
    """Accepts a URL only when it points to the backend.

    Args:
        value: URL from the payload.

    Returns:
        ``value``.

    Raises:
        InvalidPayload: If it is not an http(s) URL on the origin of
            ``backend_url`` (or of an entry in ``backend_origins``).
    """
    allowed = {_origin(url) for url in [CONFIGURATION["backend_url"], *(CONFIGURATION.get("backend_origins") or [])]}
    if not isinstance(value, str) or urlsplit(value).scheme not in ("http", "https") or _origin(value) not in allowed:
        raise InvalidPayload("URL is not on the backend")
    return value


def _origin(url: str) -> str:
    """Returns ``scheme://host[:port]`` of a URL."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _wallet_url(value: Optional[str]) -> Optional[str]:
    """Accepts a wallet link (deeplink or https).

    Args:
        value: Link from the payload; ``None`` is passed through.

    Returns:
        ``value``.

    Raises:
        InvalidPayload: If it uses a script-capable scheme or unsafe characters.
    """
    if value is None:
        return None
    if not isinstance(value, str) or not _WALLET_URL.fullmatch(value):
        raise InvalidPayload("Invalid wallet URL")
    if value.split(":", 1)[0] in _FORBIDDEN_SCHEMES:
        raise InvalidPayload("Invalid wallet URL")
    return value


def _qr_code(value: Optional[str]) -> Optional[str]:
    """Accepts a QR code image given as a PNG data URI.

    Args:
        value: Data URI from the payload; ``None`` is passed through.

    Returns:
        ``value``.

    Raises:
        InvalidPayload: If it is not a base64 PNG data URI.
    """
    if value is None:
        return None
    if not isinstance(value, str) or not value.startswith(_QR_PREFIX) or not _BASE64.fullmatch(value[len(_QR_PREFIX):]):
        raise InvalidPayload("Invalid QR code")
    return value


def _with_query(url: str, **params: Any) -> str:
    """Appends URL-encoded query parameters to a URL.

    Args:
        url: Base URL.
        **params: Parameters; ``None`` values are skipped.

    Returns:
        The URL with the parameters.
    """
    query = urlencode({k: v for k, v in params.items() if v is not None})
    if not query:
        return url
    return f"{url}{'&' if '?' in url else '?'}{query}"


@frontend.errorhandler(InvalidPayload)
def _invalid_payload(e: InvalidPayload):
    logger.warning(f"Rejected {request.path}: {e}")
    return jsonify({"status": "error", "message": str(e)}), 400


@frontend.route("/display_auth_method", methods=["POST"])
def display_auth_method():
    payload = _load_payload()
    return render_template(
        "misc/auth_method.html",
        pid_auth=payload.get("pid_auth"),
        country_selection=payload.get("country_selection"),
        redirect_url=_backend_url(payload.get("redirect_url")),
    )


@frontend.route("/display_countries", methods=["POST"])
def display_countries():
    payload = _load_payload()
    return render_template(
        "dynamic/dynamic-countries.html",
        countries=payload.get("countries"),
        session_id=payload.get("session_id"),
        redirect_url=CONFIGURATION["backend_url"],
    )


@frontend.route("/display_form", methods=["POST"])
def display_form():
    payload = _load_payload()
    return render_template(
        "dynamic/dynamic-form.html",
        mandatory_attributes=payload.get("mandatory_attributes"),
        optional_attributes=payload.get("optional_attributes"),
        redirect_url=_backend_url(payload.get("redirect_url")),
    )


@frontend.route("/display_authorization", methods=["POST"])
def display_authorization():
    payload = _load_payload()
    return render_template(
        "dynamic/form_authorize.html",
        presentation_data=payload.get("presentation_data"),
        user_id=payload.get("session_id"),
        redirect_url=_backend_url(payload.get("redirect_url")),
    )


@frontend.route("/display_pid_login", methods=["POST"])
def display_pid_login():
    payload = _load_payload()
    return render_template(
        "openid/pid_login_qr_code.html",
        url_data=_wallet_url(payload.get("deeplink_url")),
        qrcode=_qr_code(payload.get("qr_img_base64")),
        presentation_id=payload.get("transaction_id"),
        redirect_url=CONFIGURATION["service_url"],
    )


@frontend.route("/credential_offer", methods=["GET", "POST"])
def credentialOffer():
    return redirect(
        _with_query(f"{CONFIGURATION['backend_url']}/credential_offer_choice", frontend_id=CONFIGURATION["frontend_id"])
    )


def _json_metadata(document: Dict[str, Any]):
    resp = make_response(document, 200)
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@frontend.route("/.well-known/<service>")
def well_known(service):
    if service == "openid-credential-issuer":
        if "application/jwt" in request.headers.get("Accept", ""):
            resp = make_response(signed_metadata, 200)
            resp.headers["Content-Type"] = "application/jwt"
            resp.headers["Pragma"] = "no-cache"
            resp.headers["Cache-Control"] = "no-store"
            return resp
        return _json_metadata(oidc_metadata)

    if service in ("oauth-authorization-server", "openid-configuration"):
        return _json_metadata(openid_metadata)

    return make_response("Not supported", 400)


@frontend.route("/internal_error", methods=["POST"])
def display_internal_error():
    payload = _load_payload()
    # The status code is fixed: a posted payload must not choose it.
    return render_template("misc/500.html", error=payload.get("error"), error_code=payload.get("error_code")), 500


@frontend.route("/display_revocation_authorization", methods=["POST"])
def display_revocation_authorization():
    payload = _load_payload()
    return render_template(
        "misc/revocation_authorization.html",
        display_list=payload.get("display_list"),
        revocation_identifier=payload.get("revocation_identifier"),
        redirect_url=_backend_url(payload.get("redirect_url")),
        revocation_choice_url=_backend_url(payload.get("revocation_choice_url")),
    )


@frontend.route("/display_revocation_success", methods=["POST"])
def display_revocation_success():
    return render_template(
        "misc/revocation_success.html",
        redirect_url=CONFIGURATION["service_url"],
    )


@frontend.route("/display_credential_offer", methods=["POST"])
def display_credential_offer():
    payload = _load_payload()

    credentials = {"sd-jwt vc format": {}, "mdoc format": {}}
    for cred, credential in oidc_metadata["credential_configurations_supported"].items():
        name = credential["credential_metadata"]["display"][0]["name"]
        if credential["format"] == "dc+sd-jwt":
            credentials["sd-jwt vc format"][cred] = name
        if credential["format"] == "mso_mdoc":
            credentials["mdoc format"][cred] = name

    return render_template(
        "openid/credential_offer.html",
        cred=credentials,
        redirect_url=_backend_url(payload.get("redirect_url")),
        credential_offer_URI=payload.get("credential_offer_URI"),
    )


@frontend.route("/display_credential_offer_qr_code", methods=["POST"])
def display_credential_offer_qr_code():
    payload = _load_payload()

    wallet_dev = _wallet_url(payload.get("wallet_dev"))
    tx_code = payload.get("tx_code")
    code = payload.get("code")
    offer = json.dumps(payload.get("credential_offer"))
    if wallet_dev:
        if tx_code and code:
            wallet_dev = _with_query(wallet_dev, code=code, tx_code=tx_code, credential_offer=offer)
        else:
            wallet_dev = _with_query(wallet_dev, credential_offer=offer)

    return render_template(
        "openid/credential_offer_qr_code.html",
        wallet_dev=wallet_dev,
        url_data=_wallet_url(payload.get("url_data")),
        tx_code=tx_code if tx_code and code else None,
        qrcode=_qr_code(payload.get("qrcode")),
    )


@frontend.route("/display_revocation_choice", methods=["POST"])
def display_revocation_choice():
    payload = _load_payload()
    return render_template(
        "openid/revocation_choice.html",
        cred=payload.get("cred"),
        redirect_url=_backend_url(payload.get("redirect_url")),
    )


@frontend.route("/display_revocation_qr_code", methods=["POST"])
def display_revocation_qr_code():
    payload = _load_payload()
    return render_template(
        "openid/revocation_qr_code.html",
        url_data=_wallet_url(payload.get("url_data")),
        qrcode=_qr_code(payload.get("qrcode")),
        presentation_id=payload.get("presentation_id"),
        redirect_url=_backend_url(payload.get("redirect_url")),
    )
