#!/bin/bash
# Usage sudo ./md5_hashcheck_reset.sh <whitelist_dir> <scratch_file>
# Restores the value of <whitelist_dir>/md5_hashcheck.whitelist to
# the original value stored in <whitelist_dir>/<scratch_file>

output_dir="$1"
original_file="md5_hashcheck.whitelist"
scratch_file="$2"

original="$output_dir$original_file"
scratch="$output_dir$scratch_file"

cat "$scratch" > "$original"
rm "$scratch"