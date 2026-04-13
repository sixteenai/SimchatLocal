# SimChat

SimChat is a lightweight browser-based chat UI with local API-key support plus optional Cloudflare Worker backends for storage and paid-model routing.

## Project Layout

- `site/index.html` - main SimChat web app
- `site/SimpleSite.html` - smaller standalone chat page
- `worker/` - Cloudflare Worker for auth, feedback, presets, chats, and storage-backed endpoints
- `paidWorker/` - Cloudflare Worker for paid model routing

## Local Use

For simple local testing, open `site/index.html` or `site/SimpleSite.html` in a browser.

The checked-in worker config is intentionally blanked out. If you want to deploy the workers, add your own values to:

- `worker/wrangler.toml`
- `paidWorker/wrangler.toml`

and set any required Worker secrets locally before deployment.

## Notes

- No production endpoints or secrets are included in this public repo.
- If you change the app, remember to update the visible version in the UI where applicable.
