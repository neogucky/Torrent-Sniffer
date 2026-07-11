# Torrent search research index

A small, local-first application for collecting *search-result metadata* from configurable adapter-driven sources and searching it locally. It does not download torrent files, interact with trackers, solve CAPTCHAs, rotate proxies, or bypass access controls.

## What it does

- Queues remote searches and follows the source's pagination one page at a time, retaining result metadata and detail URLs in SQLite. Magnet links are fetched only when requested from an individual result.
- Searches the retained index locally, requiring every query word by default. `Ninja Turtles` therefore finds entries with both `ninja` and `turtles`, rather than either term alone.
- Keeps the source URL configurable so a legitimate, authorised mirror or an alternative compatible source can be used.
- Limits each source to one request stream and waits between every search or user-requested detail lookup. Errors (including a temporary 403) add 10 seconds to the source delay; every five consecutive successful requests remove 5 seconds, never below the initial delay. A request is retried at most five times, then the task offers **Retry this page**. Tasks can be stopped, continued, or removed, with request-level diagnostics available from **Details**.
- Provides a compact browser UI; the included Electron wrapper is optional.

## Run locally

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`. Data is stored in `data/research-index.sqlite` by default. Set `RESEARCH_INDEX_DB` to choose another path.

## Use

1. Set the source base URL to an authorised compatible instance, including its scheme, e.g. `https://example.org`.
2. Enter a remote query and queue it. The worker fetches the source’s `/search/<query>/1/` endpoint.
3. Use **Search local index** to filter all saved results. Each word must occur in the saved title; enable *include description* only if needed.

Source behaviour is defined in local adapter JSON files rather than application code. If a source’s markup differs, add a new adapter configuration rather than weakening rate limits or attempting to evade the source’s protections.

## Optional Electron shell

The frontend is regular static HTML and can be opened in any browser. To package the same UI as a desktop shell, run:

```sh
cd electron
npm install
npm start
```

The shell starts only after the FastAPI server is already running.
