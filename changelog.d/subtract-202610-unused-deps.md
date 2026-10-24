### Internal
- **Web: dropped two redundant dev dependencies.** `@typescript-eslint/eslint-plugin` and `@typescript-eslint/parser` were declared directly but nothing imports them; the flat ESLint config gets both through the `typescript-eslint` package, which still pulls in the same versions.
