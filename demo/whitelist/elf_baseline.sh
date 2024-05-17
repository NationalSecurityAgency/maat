#!/bin/bash

if [ "$#" -eq 2 ]
then
    if [ ! -d "$1" ]
    then
        echo "Target directory does not exist."
        echo "Usage: sudo ./elf_binary.sh <target-dir> <output-dir>"
        exit
    fi

if [ ! -d "$2" ]
    then
        echo "Output directory does not exist."
        echo "Usage: sudo ./elf_binary.sh <target-dir> <output-dir>"
        exit
    fi
else
    echo "Invalid number of arguments."
    echo "Usage: sudo ./elf_binary.sh <target-dir> <output-dir>"
    exit
fi

target_dir="$1"
output_dir="$2"
output_file="binary.whitelist"
pattern="W"

if [[ ! "$target_dir" == */ ]]
then
    target_dir="$target_dir/"
fi

if [[ ! "$output_dir" == */ ]]
then
    output_dir="$output_dir/"
fi

output_dir+="$output_file"

echo "#" > "$output_dir"
{
    echo "# Binary whitelist file"
    echo "#"
    echo "# File names appearing in this list (one per line) are the only"
    echo "# binaries allowed to have a writable .text ELF section header."
    echo "# The current version supports appraising binary files within the"
    echo "# target directories /bin and /lib."
    echo "# Add binary names in the form /<target-dir>/<binary-name> (e.g., /bin/ls)."
} >> "$output_dir"

for file in "$target_dir"*
do
    text_content=$(readelf -W -S "$file" | grep .text)
    case "$text_content" in
        *"$pattern"*) echo "$file" >> "$output_dir" ;;
    esac
done