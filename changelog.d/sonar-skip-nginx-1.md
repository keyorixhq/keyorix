### Internal
- **SonarCloud coverage run skips `TestWebNginxHSTS_ComposeImage`.** The `Generate coverage report`
  step in `sonarcloud.yml` now passes `-skip '^TestWebNginxHSTS_ComposeImage$'` to both `go test`
  invocations (`./...` on push, changed packages on pull requests). The test builds a docker compose
  image that exceeds the step's timeout and failed the `Analysis` check on PRs touching `./deploy`.
  The skip is name-pinned (not `-short`), so other tests and the coverage numbers are unchanged; the
  test stays covered by the docker-boot/e2e tiers and `ci.yml`.
