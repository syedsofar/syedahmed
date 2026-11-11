# Component catalog

`components.json` is the 2,549-item component library imported from the
"Security Architecture Workbench" standalone prototype (ArchGuard, supplied as
`architecture-workbench-pro.zip`). It is served to signed-in users at
`GET /api/catalog/components`.

- `components.json`: groups, components, and embedded icons (1,827 SVG, 320 PNG).
- `component-inventory.csv`: the same inventory as a spreadsheet.
- `validate_catalog.py`: checks counts, unique IDs, group reconciliation and icon types.

## Provenance and licensing

- Names and grouping come from the supplied reference files. The prototype's notes
  say they were extracted from a user-provided interface capture and have not been
  independently verified.
- The 2,147 embedded icons include AWS, Azure and Google Cloud artwork. These are
  vendor trademarks and artwork. They are included as agreed for internal use.
  Review the vendor licence and trademark terms before wider distribution.
- The 309 Azure entries have no icon file in the supplied material. They show a
  generated monogram tile instead.
- The "level" field (high/low) is a heuristic from the prototype, not a verified
  design-level classification.
