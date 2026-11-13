### Testing

- `sdkdiff hostile`: hostile-server mode for the SDK differential harness. A mock server mutates otherwise valid responses (malformed, oversized, slow, truncated) against the Go, Java, Node and Python SDK drivers, with pre-registered oracles, planted-defect validation and direct fuzzing of the Java `JsonParser` (#4043).
