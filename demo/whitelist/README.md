## Copyright

Copyright 2024 United States Government

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
 
      http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

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

## Memorymapping Appraise Whitelist:
The whitelist is used by the Memory Mapping Appraisal ASP.
Use the following command to generate the whitelist named `memorymapping_appraise_file.whitelist`.
This whitelist is placed into `<output-directory>`
```
$ chmod +x memorymapping_appraise_whitelist.sh
$ sudo ./memorymapping_appraise_whitelist.sh <target-directory> <output-directory>
```

Normally, the Memory Mapping Appraisal ASP fails if either one of these two non-mutually exclusive propertities is violated:
(1) A process spawned from a particular file cannot have both executable and writable memory mappings.
(2) The program cannot alter the in-memory representation of the mapping.

The whitelist provides a list of filepaths that are exceptions to the normal rule described above.

Before running the appraiser, the user must verify `memorymapping_appraise_file.whitelist` to ensure that the file includes all expected whitelisted files. 
Users should also specify the output directory within the directory where Maat is installed.

Below is an example when Maat is installed in `/opt/maat`:
```
$ chmod +x memorymapping_appraise_whitelist.sh
$ sudo ./memorymapping_appraise_whitelist.sh /usr/lib/ /opt/maat/share/maat/asps/
```