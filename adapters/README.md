# Local source adapters

Adapter JSON files describe how a source is searched and parsed. They are versioned with the application and can also be created or edited in the app.

Each adapter has an `id`, `label`, a search URL template, a pagination-link pattern, field extraction rules, and a magnet-link pattern. The parser supports:

- `link_href_contains`: select an anchor by a stable portion of its `href`.
- `cell_class_contains` with optional `fallback_index`: select a table cell.
- `value`: either `text` (default) or `href`.
- `as`: `integer` or `url` when conversion is required.

Create or edit an adapter in the source dialog, then select it for a source.
