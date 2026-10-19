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

Open `http://127.0.0.1:8000`. Data is stored in `data/research-index.sqlite` by default. The default is resolved relative to the application directory, so starting the server from another working directory will still use the same data. Set `RESEARCH_INDEX_DB` to choose another path.

## Use

1. Set the source base URL to an authorised compatible instance, including its scheme, e.g. `https://example.org`.
2. Enter a remote query and queue it. The worker fetches the source’s `/search/<query>/1/` endpoint.
3. Use **Search local index** to filter all saved results. Each word must occur in the saved title; enable *include description* only if needed.

Source behaviour is defined in local adapter JSON files rather than application code. If a source’s markup differs, add a new adapter configuration rather than weakening rate limits or attempting to evade the source’s protections.

Editable `adapters/*.json` files are ignored by Git. Keep private source definitions there; the bundled default remains in `app/default_adapter.json`. Field rules can use ordered `alternatives` and `row_cell_count` to handle different table layouts. Request details report missing configured fields and sizes that could not be converted to bytes, even when the HTTP request succeeded. Existing metadata is updated when its search page is crawled again.

Accounts and sessions are stored in the SQLite database. Sessions last 14 days; after expiry, log in to the existing account. Each runtime database uses its own browser cookie, so separate local instances on different ports do not replace each other's logins. Valid cookies from earlier versions are migrated without another sign-in. Authentication responses are not cached, and returning to a restored browser page rechecks the session. If a session expires while editing a source, signing in resumes the open form with its unsaved inputs.

## Regression checks

```sh
python -m unittest discover -s tests -v
```

## Optional Electron shell

The frontend is regular static HTML and can be opened in any browser. To package the same UI as a desktop shell, run:

```sh
cd electron
npm install
npm start
```

The shell starts only after the FastAPI server is already running.

## Account source connector

Select **RuTracker (account required)** and configure its HTTPS base URL at runtime. Open **Edit source**, paste the full browser **Request headers**, then click **Save and test**. Copy the headers from a signed-in tracker page request in developer tools → Network. HTTP/1 request lines and HTTP/2 pseudo-headers are accepted. Browser table copies with split name/value lines, tabs, flattened headers and common line endings are normalized before validation. Missing Cookie, User-Agent or `bb_session` values are reported before anything is saved. A copied hostname must match the source URL when present. Blank input keeps a complete saved session.

The connector retains cookies and supported browser preferences. It encrypts them in the runtime database, discards the raw header block, and reuses the imported User-Agent for source requests. Saved values remain write-only. Browser verification may still reject imported sessions.

The encryption key is stored with owner-only permissions in `source-secrets.key` beside the database, or supplied through `SOURCE_SECRETS_KEY`. Preserve the database and key together across restarts and deployments. The runtime database, key, `.env`, and editable adapter JSON files are ignored by Git. No hostname, account or session is bundled. Source sessions can only be configured by an application administrator.

RuTracker searches use its tracker endpoint with an explicit all-forums scope and 50-result page offsets. Only topic links in the torrent table's title column are collected; navigation and search-help topics are ignored, including when a search has no matches. Connector protocol reference: [Jackett's RuTracker implementation](https://github.com/Jackett/Jackett/blob/master/src/Jackett.Common/Indexers/Definitions/RuTracker.cs). Live account access still needs to be verified against your configured source; no real account is included in tests.

## Wishlist and archive

Open the wishlist from the bookmark button beside Settings. Its badge counts active wishes only; archived entries are available inside the modal. The wishlist is shared by signed-in users, like the local result index. Add a movie or series with its search term, then use **Crawl selected source** or **Search local**. Local searches close the modal and display their results on the main page. Any crawl started from the ordinary remote-search field automatically creates a wishlist entry as well. Equivalent terms are deduplicated using the same word normalization as local search, ignoring case, punctuation, repeated words, and word order.

Each entry shows its number of distinct linked results, whether a crawl has completed (including zero-result crawls), and active crawl status. Click the result count to inspect the linked results, or **Search local** to search the whole local index. Existing size, availability, and exclusion filters still apply. Repeated or overlapping crawls retain associations without inflating the count. Existing crawl history and result associations are migrated on first startup.

A successful qBittorrent download request moves related wishes to **Archive**, regardless of where the search started. Matches use crawl associations, the local search term, and whole-word title matching against active wishes, so a manually added wish can be fulfilled by a result found through a different query. Failed requests leave wishes active. Opening a fetched magnet link also archives matching wishes when handed to your external client; the browser cannot confirm whether that client actually started or finished the download. Fetching a magnet alone does not archive anything. **Restore** moves a wish back; re-crawling an archived term keeps it archived until restored. **Remove** deletes a wish while retaining collected results; stop active crawls first.

## Checks

```sh
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
node --check app/static/app.js
.venv/bin/ruff check --isolated --select E4,E7,E9,F,I app tests
```

Tests use temporary databases and simulated source responses. They do not log into a real source, download content, or require credentials.
