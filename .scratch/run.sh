#!/usr/bin/env bash
set -uo pipefail
source /mnt/data/wave4/rvf1/.scratch/env.sh
cd /mnt/data/wave4/rvf1
nice -n 10 "$@"
