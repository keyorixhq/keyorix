### Fixed
- **Cancelled scheduler ticks stop cleanly.** When a scheduler lock is lost or the server shuts down mid-tick, auto-rotation no longer reports the secrets it had not reached as failed, and evidence delivery no longer publishes a signed pack that is incomplete only because the tick was cancelled. Both are picked up by the next tick.

### Documentation
- **Advisory-lock overlap window.** `docs/design/pooler-lock-loss.md` records the accepted window for separation-of-duties grants and dual-control approvals, and what a double run does for each scheduler job.
