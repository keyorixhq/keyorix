### Internal
- **Web: removed code nothing imports** (found by knip, each confirmed by grep): six page/service barrel `index.ts` files, eight unused constant groups in `src/constants.ts`, `formatDay`, unused test mocks and form helpers, and `src/test/README.md`, which documented helpers, files and scripts that do not exist. No behaviour change.
