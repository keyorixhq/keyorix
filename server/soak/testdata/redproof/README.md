# Red-proof plants for the soak oracles

`plant_*.go.txt` are throwaway leaks (a goroutine that never exits, an unclosed `sql.Rows`, a leaked temp file, an open fd), kept as `.txt` so no build or scanner treats them as code. `run.sh` copies one in as `server/soak/zz_plant_test.go`, runs the smoke, checks that the right oracle failed, and removes it; it also runs the plant-free control, which must be green. (`scripts/fuzzing/oracle-health` did not exist on origin/main when this was written, so the plants live here.)
