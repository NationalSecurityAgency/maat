#!/bin/bash
# Usage sudo ./md5_hashcheck_add.sh <whitelist-dir> <target-dir>
# Adds all of the files in <target-dir> to the whitelist <whitelist-dir>/md5_hashcheck.whitelist

if [ "$#" -eq 2 ]
then
    if [ ! -d "$1" ]
    then
        echo "Whitelist directory does not exist."
        echo "Usage: sudo ./md5_hashcheck_add.sh <whitelist-dir> <target-dir>"
        exit
    fi

if [ ! -d "$2" ]
    then
        echo "Target directory does not exist."
        echo "Usage: sudo ./md5_hashcheck_add.sh <whitelist-dir> <target-dir>"
        exit
    fi
else
    echo "Invalid number of arguments."
    echo "Usage: sudo ./md5_hashcheck_add.sh <whitelist-dir> <target-dir>"
    exit
fi

whitelist_dir="$1"
target_dir="$2"

if [[ ! "$whitelist_dir" == */ ]]
then
    whitelist_dir="$whitelist_dir/"
fi

whitelist="$whitelist_dir/md5_hashcheck.whitelist"

for file in "$target_dir"*
do
    if [ -f "$file" ]
    then
        hash=$(md5sum "$file" | head -c 32)
        echo "$file:$hash" >> "$whitelist"
    fi
done
