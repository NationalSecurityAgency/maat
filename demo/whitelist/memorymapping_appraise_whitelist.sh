#!/bin/bash

# This script generates a whitelist named memorymapping_appraise_file.whitelist,
# that contains paths of files in forms of: 
# <target-directory>/<filename> or <target-directory>/<sub-directories>/<filename>

# In particular, if we run the script when target-directory is set to /usr/lib/
# the content of the whitelisted file can be a list of filepaths in form of 
# /usr/lib/<sub-directories><filename> or /usr/lib/<filename>.

# For example:
# /usr/lib/systemd/systemd
# /usr/lib/x86_64-linux-gnu/ld-2.31.so
# /usr/lib/cnf-update-db

# The whitelist is used by the Memory Mapping Appraisal ASP.
# This whitelist contains a list of filepaths which specify a set of processes that, 
# when spawned from the indicated file, may have executable and writable memory 
# mappings and may alter the in-memory contents of the mapping.

if [ "$#" -eq 2 ]
then
    if [ ! -d "$1" ]
    then
        echo "Target directory does not exist."
        exit
    fi

if [ ! -d "$2" ]
    then
        echo "Whitelist directory does not exist."
        exit
    fi
else
    echo "Invalid number of arguments."
    exit
fi

target_dir="$1"
whitelist_dir="$2"

if [[ ! "$whitelist_dir" == */ ]]
then
    whitelist_dir="$whitelist_dir/"
fi

whitelist="$whitelist_dir/memorymapping_appraise_file.whitelist"

find "$target_dir" -type f -executable -print > "$whitelist"
