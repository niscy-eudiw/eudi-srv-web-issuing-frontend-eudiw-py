## [0.9.4]

_02 Apr 2026_

### Added
- Sign metadata support

### Changed
- Configuration to yaml
- install.md

## [0.9.5]

_05 Aug 2026_

### Added
- Forwarding additional headers in pushed authorization requests.

## [0.9.6]

_06 Oct 2026_

### Added
- `backend_api_key` configuration: sent to the backend to load this frontend's metadata.
- `backend_origins` configuration (optional): other public origins of the backend.
- Content-Security-Policy, `X-Frame-Options`, `X-Content-Type-Options` and `Referrer-Policy` headers.
- Test suite (`tests/`) and a CI workflow running it.

### Changed
- Metadata is loaded from the backend (`/metadata/<frontend_id>` and `/metadata/<frontend_id>/signed`) instead of being built from local templates; `credentials_supported` and `oauth_url` for the metadata are now configured in the backend.
- Pages only post to and navigate to URLs on the backend origin, wallet links must use a scheme that cannot run code, and QR codes must be PNG data URIs: the `payload` form field can be posted by anyone.
- CORS only allows the public metadata (`/.well-known/*`), without credentials; it reflected any origin with cookies.
- The frontend keeps no session: `SECRET_KEY="dev"` and Flask-Session were removed.
- The pushed authorization proxy relays only safe upstream headers and returns generic errors.
- jQuery is served locally.
- The Docker image runs as an unprivileged user (UID 10001) and only copies `app/`.
- CI: SonarCloud runs on `pull_request` instead of `pull_request_target` and actions are pinned to commit SHAs.
- Removed unused `app/misc.py`, `app/static/jwks.json` and the local metadata templates.

### Fixed
- XSS through `javascript:` URLs in links, form actions and the revocation page's inline `onclick`.
- XSS through payload values inside `<script>` blocks (revocation and PID login pages): values are now JSON encoded.
- DOM XSS in the attribute form, where attribute names were inserted with `innerHTML`.
- `/internal_error` no longer takes its HTTP status from the posted payload.
- Raw payloads, request bodies and headers are no longer logged or printed.
- Pages use the `strict-origin` referrer policy instead of `no-referrer`: with `no-referrer` browsers send `Origin: null` on form posts, which the backend's CSRF check rejects.
- The Content-Security-Policy has no `form-action`: browsers apply it to redirects too, which blocked the backend's redirect to the authorization server after consent.

## [Unreleased]

### Changed
- Templates share one page frame, `layout/base.html` (head, header, main container), with `layout/_footer.html`, `openid/_credential_select.html` (credential checkboxes, buttons, submit script), `openid/_qr_code.html` and `openid/_oid4vp_qr_code.html` (the PID login and revocation QR pages differ only in three URLs). The seven pages SonarCloud reported as duplicated (13.6% of the lines) keep their names and output; the error and start pages gain the viewport meta tag, and an unused `#check` script is gone from the QR pages.
- Boolean toggles in the attribute form: the switch's own label carries the field name (screen-reader text); the visible title is no longer a second label.
- SonarCloud reliability: the PAR relay reads wallet headers with `.get()` and returns a `Response` on every path (it mixed 3- and 2-tuples); the unauthenticated-payload handler returns its 400 as a plain `(page, 400)` tuple. Templates: labels tied to their controls, `alt` text on images, no `accesskey`, headings with accessible text.
- The PAR relay no longer logs the wallet's `client_id` (SonarCloud log injection; the authorization server logs the authenticated client). Comments at `create_app` and the CORS setup record why the CSRF (S4502) and CORS (S5122) hotspots are safe, and both are marked `# NOSONAR`.
- `requests` 2.32.3 → 2.34.2 (PYSEC-2026-1872, PYSEC-2026-2275), `werkzeug` 3.1.6 → 3.1.9 (CVE-2026-102598), `Flask-Cors` 6.0.2 → 6.0.5, matching the backend.
- Removed requirements nothing imports: `Flask-Session`, `flask_api`, `validators`, `jsonschema` and `config`.
- Display payloads can be authenticated: with the new `payload_key` configuration the `/display_*` pages and `/internal_error` require `payload_jwt`, an HS256 JWT from the backend (claims `payload`, `aud` = `frontend_id`, `iat`, `exp`, lifetime at most 300 s, 60 s clock skew), and use its `payload` claim; the plain `payload` field is ignored. A missing or invalid token gets `400` with a generic page. Without `payload_key` a warning is logged at start-up.
- Each page only accepts the backend endpoint it posts to or links to (e.g. `/display_form` → `<backend>/dynamic/form` or `/preauth_form`), on top of the same-origin check.
- Wallet links on the QR code pages must be `scheme://...` links with no characters that could leave an HTML attribute, and not use a scheme that runs code or reads local data (`javascript`, `data`, `vbscript`, `file`, `blob`, `about`). This is the rule the backend applies to the credential offer URI chosen on `/display_credential_offer`, so custom wallet schemes and https wallet links work.
- Metadata requests to the backend (which carry `X-Api-Key`) do not follow redirects, and start-up fails when `backend_url` is not https, except for `localhost`, `127.0.0.1` and `::1`.
- The pushed authorization proxy sends the wallet's address (`request.remote_addr`) in `X-Forwarded-For` so the authorization server can rate-limit per wallet (`trusted_proxies: 1` there). Request bodies are limited to 1 MiB (`max_content_length`).
- Content-Security-Policy: `script-src` no longer allows `'unsafe-inline'`; inline scripts carry a per-request nonce and inline event handlers moved to `static/scripts/page-actions.js`. `style-src` is `'self' 'unsafe-inline'` instead of any https origin.
- `/.well-known/oauth-authorization-server` serves the backend's OAuth authorization server metadata instead of the OpenID configuration.
- Removed the unused templates `misc/eidas_fail.html` and `dynamic/pt_url.html` and the unused `werkzeug.debug` import.
- The revocation link on the start page and the "back" link of the revocation consent page pass `frontend_id`, so the backend lists only the credentials this frontend publishes.
- The consent page shows as images the attributes the backend names in `image_attributes` (default: `portrait`, `picture`, `image`, `signature_usual_mark`, `signature_usual_mark_issuing_officer`, `issuing_authority_logo`).
- Pages posted by the backend log `, Session ID: <id>, Page: <route>` like the backend and authorization server, so an issuance can be followed across the components; a session id that is not a plain token is logged as `<invalid>`.

### Fixed
- The PID login page polled `<service_url>pid_authorization` (missing `/`, on the frontend) and then opened `/getpidoid4vp` on the frontend; it now polls `<backend_url>/pid_authorization` and opens `<backend_url>/getpidoid4vp`.
- `Accept: application/jwt` on `/.well-known/openid-credential-issuer` without signed metadata returns `406` instead of `500`.
- The 404 handler logs one line instead of a stack trace.
- The "back" links of the PID login and revocation QR pages pointed to frontend paths that do not exist; they go to the backend's `/auth_method_choice` and `/revocation/revocation_choice`.
- QR codes were rendered at the backend's 2-3 px per module, too small for some phones to scan; they are scaled to 200-280 px with `image-rendering: pixelated`.
