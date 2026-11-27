### Changed
- The setup-link email MIME fuzz oracle now treats an encoded-word lookalike whose encoded text contains `?` (for example an empty charset with the text `?`) as the display-spoofing limit it already models, instead of failing the Subject round-trip. Test-only; no product code changes.
