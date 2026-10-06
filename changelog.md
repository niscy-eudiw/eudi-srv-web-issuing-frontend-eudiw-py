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
