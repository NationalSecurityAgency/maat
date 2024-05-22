## elf_baseline.sh

The `elf_baseline.sh` generates a baseline list of binaries in which the `.text` section header is writable. The binary files checked by this script should be those located within the same directory targeted by the userspace ELF measurement specification (e.g., `/bin/` or `/lib/`). See `userspace_elf_mspec.xml` for more details. 

The whitelisted binaries are saved in the `/<output-dir>/binary.whitelist` file. The `maat` user must verify that the `binary.whitelist` file includes all expected whitelisted binaries before running any subsequent ELF appriasal.

### Requirements

- `readelf` (tested with version v2.38).
- Sudo access

### Usage

```
chmod +x elf_baseline.sh
sudo ./elf_baseline.sh <target-dir> <output-dir> 2>/dev/null
```

The user may choose to remove the `2>/dev/null` from the command above to output any potential errors generated during the script execution. For ELF appraisals using Maat, the user shall specify an output directory within `/op/maat`. An example below:

```
sudo ./elf_baseline.sh <target-dir> /opt/maat/share/maat/asps/ 2>/dev/null
```