### Testing

- The crash-recovery fuzz harness no longer loses a directory change made just before the child exits, and `TestRunChild_RecordsChangeWindow` no longer depends on poller scheduling.
