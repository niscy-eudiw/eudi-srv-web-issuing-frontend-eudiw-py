# Configuration

For configuring your locally installed version of the EUDIW Issuer Front-end, you need to change the following configurations.

## 1. Service Configuration

Base configuration example for the EUDIW Issuer Front-end is located in ```frontend_config_example.yaml```.

Parameters that should be changed:

- `service_url` (Base url of the service)
- `frontend_id` (The front-end id registered in the backend service)
- `backend_url` (Public base url of the back-end service; pages only post to, and navigate to, URLs on this origin)
- `backend_origins` (Optional list of other public origins of the back-end, if browsers reach it under more than one)
- `oauth_url` (Base url for the authorization service)
- `backend_api_key` (API key sent to the backend in the `X-Api-Key` header; must match the backend's `backend_api_key`)
- `log_dir` (Log directory)

The front-end's metadata (`/.well-known/openid-credential-issuer`, `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`) is loaded from the backend at start-up (`GET /metadata/<frontend_id>` and `GET /metadata/<frontend_id>/signed`). The credentials it advertises (`credentials_supported`) and the authorization server it points to (`oauth_url`) are therefore configured in the backend, under `frontend.frontends_config.<frontend_id>`.
