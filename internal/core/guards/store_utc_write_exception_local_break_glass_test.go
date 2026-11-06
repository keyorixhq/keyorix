package guards

func init() {
	registerStoreScanSkip("local_break_glass.go",
		"UTC-SOLEWRITER-TAILS-1 #3914: break-glass cutoffs and writers move to the sole writer; not scanned here, not edited by "+
			"UTC-STORE-SCAN-1 (its map writes carry .UTC() today). Remove this file when the sole writer owns them")
}
