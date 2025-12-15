## 2024-05-23 - Visual Polish for CLI Histogram
**Learning:** Using block characters (`█`) instead of `#` significantly improves the perceived quality of CLI tools. It makes histograms look like solid bars rather than ASCII art, which feels more professional and easier to read at a glance. Aligning the trailing count using string formatting (e.g., `:<40`) also helps with readability by creating a consistent grid.
**Action:** When designing CLI dashboards or stats outputs, default to block characters and ensure consistent alignment for variable-length visual elements.
