### Testing

- `FuzzAuditChainMetamorphicTamper` builds each audit chain once per process and event count and gives every input a private copy of the file, instead of rebuilding it through the write path for every input. About 3.6x more executions per second on the same hardware (88/s to 317/s at `-parallel 1`, 315/s to 1,098/s at `-parallel 4`). The oracle, the mutations and the fingerprints are unchanged; an input that mutates its copy cannot reach the template or another input, and a template file whose bytes changed is refused.
