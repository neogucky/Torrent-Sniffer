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

Accounts and sessions are stored in the SQLite database. Sessions last 14 days; after expiry, log in to the existing account. Authentication responses are not cached, and returning to a restored browser page rechecks the session.

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

Select **RuTracker (account required)** in **Add source** and enter the site's HTTPS base URL at runtime (without a `/forum` path). The bundled connector contains parsing and login support only: no site hostname, account, session, or preconfigured source is committed. Source accounts can only be configured, changed, or removed by an application administrator.

Choose **Saved username and password** for automatic login and session renewal. Save the source or use **Save and test login**. Both search pages and on-demand magnet lookups use the same source session. Blank account fields keep the saved values; changing the URL or adapter discards the previous login and cached magnets, so enter the login again. A fresh account session starts with the login page, retains its session cookie and hidden form fields, then submits the login before requesting protected pages. Login requests share a serialized, paced stream with authenticated source requests. HTTP errors identify the step that failed and remain visible after reopening Edit source; an HTTP 403 is an access refusal, not proof of an incorrect password. Browser login and programmatic access can be treated differently by a source, so a saved account or imported cookie does not guarantee that a refused HTTP request will be accepted.

When the site requires a CAPTCHA, log in yourself in a browser on the same network as the server. Open browser developer tools → Network, load the tracker page, select its request, and copy the **Cookie** request header value. Select **Browser session cookie**, paste that value, and save/test. A session cookie grants account access: treat it like a password. Replace it after expiry. The app reports authentication failures and stops the crawl so you can update the login and retry the failed page.

Account passwords and session cookies are encrypted with Fernet in the runtime SQLite database. The key is created with owner-only permissions at `source-secrets.key` beside the database. Keep that key across restarts and deployments; it is required to decrypt saved logins. Alternatively, supply a Fernet key through the `SOURCE_SECRETS_KEY` environment variable using your deployment's secret storage. Changing the environment key requires restoring the old key or replacing saved source logins. Back up the database and key securely; anyone with both can decrypt the logins. The default `data/` directory, key files, database files, `.env`, and editable adapter JSON files are ignored by Git. Keep custom runtime paths outside tracked source files too.

Connector protocol reference: [Jackett's RuTracker implementation](https://github.com/Jackett/Jackett/blob/master/src/Jackett.Common/Indexers/Definitions/RuTracker.cs). Live account access still needs to be verified against your configured source; no real account is included in tests.

## Wishlist and archive

The wishlist is shared by signed-in users, like the local result index. Add a movie or series with its search term, then use **Crawl selected source** or **Search local**. Any crawl started from the ordinary remote-search field automatically creates a wishlist entry as well. Equivalent terms are deduplicated using the same word normalization as local search, ignoring case, punctuation, repeated words, and word order.

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
