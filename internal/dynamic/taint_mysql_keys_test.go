//go:build taintoverlay

package dynamic

import _ "embed"

//go:embed testdata/taint-keys.txt
var taintMySQLKeysRaw string
