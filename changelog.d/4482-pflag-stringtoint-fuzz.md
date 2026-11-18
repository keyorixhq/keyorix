### Testing
- **spf13/pflag hostile-argv fuzz target now covers `StringToInt`.** `FuzzPflagParse` (`fuzz/thirdparty/spf13pflag`) registers a `StringToInt` flag and seeds that reach its per-pair `strconv.Atoi` parser and the empty-value paths. No separate pflag target is added.
