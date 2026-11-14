### Testing
- **Swarm testing for the stateful fuzzers.** Added a reusable feature-mask
  decoder (`internal/fuzzutil.Swarm`) and wired it into the stateful
  authorization-sequence and OpenAPI-sequence fuzz targets, each taking a swarm
  mask as the first fuzz argument. Each execution now exercises a random subset
  of the operation alphabet instead of the whole alphabet every time, which
  reaches operation interactions that uniform generation under-exercises. The
  existing seed corpus keeps its meaning (an all-ones mask is the full
  alphabet), guarded by a seed-compatibility test.
