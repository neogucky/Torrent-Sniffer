# Local source adapters

Adapter JSON files describe how a source is searched and parsed. These editable files are local configuration, ignored by Git, and can be created or edited in the app. Only the bundled default in `app/default_adapter.json` is versioned; keep private source rules in this directory.

Each adapter has an `id`, `label`, a search URL template, a pagination-link pattern, field extraction rules, and a magnet-link pattern. The parser supports:

- `page_offset`: adjust the app’s one-based page number for sources that start at zero.
- `pagination.href_regex`: use a capturing group for the source page number; pages greater than the current source page are queued automatically.
- `link_href_contains`: select an anchor by a stable portion of its `href`.
- `cell_class_contains` with optional `fallback_index`: select a table cell.
- `cell_attribute_equals` with optional `match_index`: select the indexed cell matching HTML attributes such as `align="right"`.
- `text_regex`: extract a capture group from the selected cell text.
- `alternatives`: try an ordered array of field rules until one extracts a value.
- `row_cell_count`: apply a field rule only to rows with this number of cells, for sources with multiple layouts.
- `value`: either `text` (default) or `href`.
- `as`: `integer` or `url` when conversion is required.

Create or edit an adapter in the source dialog, then select it for a source.
