### Changed
- **Merge-queue slimming can now be enforced per lever (ci.yml).** The `select` job
  passes `MQ_SLIM_LEVERS` to `scripts/ci/mq_slim.py`, the `leg_tests` and `gate_*`
  outputs reach the legs, and the seven guard skips that no shadow decision measures
  become their own `guards` lever, which a sampled full run also runs. With the
  repository variables unset nothing changes (shadow).
