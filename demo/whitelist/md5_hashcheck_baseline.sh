#!/bin/bash
# Usage md5_hashcheck_baseline.sh <whitelist_dir> <scratch_file> <datafiles_dir>
# Initializes a whitelist in <whitelist_dir>/md5_hashcheck.whitelist that contains some test datafiles and their hashes
# some of which have incorrect hashes for testing purposes
# Stores the previous value of <whitelist_dir>/md5_hashcheck.whitelist in the scratch file <whitelist_dir>/<scratch_file>


output_dir="$1"
original_file="md5_hashcheck.whitelist"
scratch_file="$2"
datadir="$3"

original="$output_dir$original_file"
scratch="$output_dir$scratch_file"

cat "$original" > "$scratch"


echo "#" > "$original"
{
    echo "# MD5 hashes whitelist file"
    echo "#"
    echo "# File hahes appearing in this file (one per line) are the only"
    echo "# files allowed on the system.  Any file hash found not on this"
    echo "# list will trigger an attestation failure"
    echo "# Add whitelisted files in the form <filename>:<hash>"
} >> "$original"

file1_name="$datadir""test_md5_hashcheck_ex_file.txt"
file2_name="$datadir""test_md5_hashcheck_whitelist.txt"
file3_name="$datadir""test_md5_hashcheck_ex_file2.txt"

file1_hash=$(md5sum "$file1_name" | head -c 32)
file2_hash=$(md5sum "$file2_name" | head -c 32)
{   #populate whitelist with some correct and some incorrect hashes
    echo "$file1_name:$file1_hash"
    echo "$file2_name:$file2_hash"
    echo "$file3_name:196b234040cd23ef08624b5322af8dfe"
} >> "$original"