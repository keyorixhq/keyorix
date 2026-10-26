# retry-net.sh fixtures

Real error lines, copied from the check-run annotations or logs of failed
merge-queue jobs (workflow CI, event merge_group), except where noted.
`retry_net_test.go` feeds each one to `retry-net.sh` on stderr.

| File | Source | Expected |
|---|---|---|
| `proxy-tls-timeout.txt` | licenses, "go-licenses check (operator module)", 2026-10-03, run 37154248108, job 111294323112 | retry |
| `proxy-stream-error.txt` | licenses, "go-licenses check (root module)", 2026-10-20, run 39506329627, job 118916116736 | retry |
| `dockerhub-500.txt` | demo-up-smoke, up.sh image build, 2026-10-23, run 39957932414, job 120435083567 (helm-boot-smoke job 120435055979 failed the same way on nginx:alpine) | retry |
| `dockerhub-unauthorized.txt` | docker-boot-smoke, "Set up Docker Buildx" pulling moby/buildkit, 2026-10-23, run 39957930614, job 120437417632 | retry |
| `compile-error.txt` | preflight vet, 2026-10-05 (class C, two PRs fine alone), sample 10-05-cheap-37257439811 | no retry |
| `init-secrets-refusal.txt` | docker-boot-smoke, "Bring up the stack", 2026-10-21, run 39686117368, job 119522014802 | no retry |
| `localhost-refused.txt` | helm-boot-smoke dump step (kubectl against no cluster), 2026-10-17, run 39066447549 | no retry |
| `gosum-mismatch.txt` | NOT from the queue: real stderr of `go mod download` (go1.27) in a module whose go.sum carries a wrong hash for github.com/pquerna/otp v1.5.0 | no retry |
| `gosum-mismatch-plus-network.txt` | `gosum-mismatch.txt` followed by `proxy-tls-timeout.txt` | no retry (integrity wins) |
