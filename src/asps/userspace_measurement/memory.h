/*
 * Copyright 2023 United States Government
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef MEMORY_H
#define MEMORY_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <glib.h>

typedef struct {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    char *path;
    char *perms;
} memory_mapping;


typedef struct {
    uint64_t start;
    uint64_t end;
    char *path;
    GSList *mappings;
} mapping_group;

// Each ELF object from the other process's image gets pulled in as one
// contiguous block so that offsets from the start of the ELF header
// are preserved. So if the dynamic segment was at offset 0x200e28 from
// the ELF header in the other process's address space, it will also be
// at offset 0x200e28 from the start of the ELF header in this buffer.
//
// There are gaps of unused memory in the buffer to match the space
// between mappings in the other process or for unreadable mappings.
// They are zeroed out here but will not trigger an access violation.
typedef struct {
    char *buf;
    char *path;
    uint64_t start;
    size_t sz;
} file_mapping_buffer;

/**
 * Open a fd which allows for reading and writing of a process' memory
 * with a pid representing by pid_string. Returns -1 if the fd could
 * not be opened
 */
int open_mem_fd(const char *pid_string);

/**
 * Read up to count bytes from start_addr into the buffer dest.
 * Return the number of bytes read or 0 if there was an error
 */
size_t read_into(void *dest, uint64_t start_addr, size_t count);

/**
 * Read bytes from the memory of a process (opened with a previous call
 * to open_mem_fd) starting at addr until a null byte is reached. If
 * the read fails, return NULL
 */
char *read_string(uint64_t addr);

/**
 * Create a structure which represents multiple memory maps of the same
 * path, starting with the given memory mapping. Returns NULL if
 * memory could not be allocated for the structure, otherwise, a
 * pointer to the structure is returned
 */
mapping_group *create_mapping_group(memory_mapping *mapping);

/**
 * Get information regarding a memory mapping of a file with a path
 * target_path in a process with a pid of pid. Returns NULL if the
 * mapping cannot be found or some other error occurs
 */
memory_mapping *get_mapping(const char *pid, const char *target_path);

/**
 * Given the PID of some process, return a GSList of mapping groups
 * representing the data mapped into the process's memory, or NULL
 * upon an error
 */
GSList *get_elf_mapping_groups(const char *pid);

/**
 * Prints diagnostic information about each mapping_group contained
 * in the list. Useful for debugging
 */
void print_mapping_groups(GSList *mapping_groups);

/**
 * Map an ELF object into the memory of the current process (see the comments
 * on the file_mapping_buffer struct for more details). Return NULL if this
 * fails.
 */
file_mapping_buffer *create_file_mapping_buffer(mapping_group *grp);

/**
 * Given a list of elf_mapping_groups, return a list of file_mapping_buffer
 * structs which represent the data of the ELF objects represented by the
 * elf_mapping_groups mapped into memory. Returns NULL if an error occurs.
 */
GSList *get_elf_buffers(GSList *elf_mapping_groups);
#endif
