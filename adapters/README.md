# Local source adapters

Adapter JSON files describe how a source is searched and parsed. They are versioned with the application and can also be created or edited in the app.

Each adapter has an `id`, `label`, a search URL template, a pagination-link pattern, field extraction rules, and a magnet-link pattern. The parser supports:

- `page_offset`: adjust the app’s one-based page number for sources that start at zero.
- `pagination.href_regex`: use a capturing group for the source page number; pages greater than the current source page are queued automatically.
- `link_href_contains`: select an anchor by a stable portion of its `href`.
- `cell_class_contains` with optional `fallback_index`: select a table cell.
- `cell_attribute_equals` with optional `match_index`: select the indexed cell matching HTML attributes such as `align="right"`.
- `text_regex`: extract a capture group from the selected cell text.
- `value`: either `text` (default) or `href`.
- `as`: `integer` or `url` when conversion is required.

Create or edit an adapter in the source dialog, then select it for a source.
