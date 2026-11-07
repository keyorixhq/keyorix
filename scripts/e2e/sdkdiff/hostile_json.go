package main

// JSONTestSuite conformance table for the decoders the SDKs call (mechanism B of hostile/RULES.md): Go
// json.Decoder.Decode, Python json.loads on bytes, Node JSON.parse on the UTF-8 string. y_ must accept, n_ must reject,
// i_ is recorded. The corpus is pinned in hostile/jsonparser/fetch-tools.sh.

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func cmdJSONTable(args []string) error {
	fs := flag.NewFlagSet("hostile jsontable", flag.ExitOnError)
	corpus := fs.String("corpus", "", "JSONTestSuite test_parsing dir")
	root := fs.String("root", ".", "sdkdiff source dir")
	_ = fs.Parse(args)
	absAll(corpus, root)
	ents, err := os.ReadDir(*corpus)
	if err != nil {
		return err
	}
	res := map[string]map[string]string{"go-decoder": {}, "go-unmarshal": {}, "python": {}, "node": {}}
	var names []string
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, e.Name())
		b, err := os.ReadFile(filepath.Join(*corpus, e.Name())) // #nosec G304 -- operator path
		if err != nil {
			return err
		}
		var v any
		if json.NewDecoder(bytes.NewReader(b)).Decode(&v) == nil {
			res["go-decoder"][e.Name()] = "accept"
		} else {
			res["go-decoder"][e.Name()] = "reject"
		}
		var w any
		if json.Unmarshal(b, &w) == nil {
			res["go-unmarshal"][e.Name()] = "accept"
		} else {
			res["go-unmarshal"][e.Name()] = "reject"
		}
	}
	for kind, argv := range map[string][]string{
		"python": {"python3", "-I", filepath.Join(*root, "hostile", "jsonparser", "table.py"), *corpus},
		"node":   {"node", "--stack-size=984", filepath.Join(*root, "hostile", "jsonparser", "table.js"), *corpus},
	} {
		out, err := exec.Command(argv[0], argv[1:]...).Output() // #nosec G204 -- fixed operator scripts
		if err != nil {
			return fmt.Errorf("%s: %w", kind, err)
		}
		for l := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
			if n, r, ok := strings.Cut(l, "\t"); ok {
				res[kind][n] = r
			}
		}
	}
	sort.Strings(names)
	for _, kind := range []string{"go-decoder", "go-unmarshal", "python", "node"} {
		var yOK, yN, nRej, nN, iAcc, iN int
		var yBad, nBad, iList []string
		for _, n := range names {
			r := res[kind][n]
			switch n[0] {
			case 'y':
				yN++
				if r == "accept" {
					yOK++
				} else {
					yBad = append(yBad, n+"="+r)
				}
			case 'n':
				nN++
				if r != "accept" {
					nRej++
				} else {
					nBad = append(nBad, n)
				}
			case 'i':
				iN++
				if r == "accept" {
					iAcc++
				}
				iList = append(iList, n+"="+r)
			}
		}
		fmt.Printf("%-13s y_ accepted %d/%d | n_ rejected %d/%d | i_ accepted %d/%d\n", kind, yOK, yN, nRej, nN, iAcc, iN)
		if len(yBad) > 0 {
			fmt.Printf("   y_ not accepted: %s\n", strings.Join(yBad, " "))
		}
		if len(nBad) > 0 {
			fmt.Printf("   n_ accepted (%d): %s\n", len(nBad), strings.Join(nBad, " "))
		}
		fmt.Printf("   i_: %s\n", strings.Join(iList, " "))
	}
	return nil
}
