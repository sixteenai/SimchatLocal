# SimChat Local

SimChat Local is a local-only chat frontend inspired by SillyTavern.

## What it is

- A browser app you run locally.
- Presets, chats, settings, and local assets stay on your machine.
- Model requests go directly from the browser to the provider you configure.

## Supported providers

- Anthropic
- OpenAI
- Google

## Running locally

Serve the `site/` directory with any static file server, then open it in your browser.

Example:

```powershell
cd site
python -m http.server 8000
```

Then open `http://localhost:8000`.

## Data storage

SimChat Local stores app data in browser storage on the local machine, primarily IndexedDB and localStorage.

## Not included

- No SimChat account system
- No cloud sync
- No worker-issued identity or cookies
- No SimChat-hosted proxy or paid worker routing
