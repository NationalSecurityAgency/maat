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

#include <util/util.h>
//#include <libexplain/ptrace.h>

#include "memory.h"

/* Represents the number of digits that the largest PID can be represented in
 * Declared in got_measurer.c
 */
extern uint32_t g_num_digits_pid;

// File descriptor for accessing memory in the other process.
static int mem_fd = -1;

int open_mem_fd(const char *pid_string)
{
    char path[PATH_MAX] = "/proc/";
    strncat(path, pid_string, g_num_digits_pid);
    strncat(path, "/mem", 5);

    errno = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        dlog(0, "Failed to open %s: %s\n", path,
             strerror(errno));
        return -1;
    }

    mem_fd = fd;
    return fd;
}

size_t read_into(void *dest, uint64_t start_addr, size_t count)
{
    ssize_t bytes_read = 0;
    size_t total_bytes_read = 0;

    while (total_bytes_read < count) {
        errno = 0;
        bytes_read = pread(mem_fd, (void *)(dest + total_bytes_read),
                           count - total_bytes_read,
                           (off_t)(start_addr + total_bytes_read));

        if (errno) {
            dlog(4, "Read call to pread in function read_into failed with error %s\n",
                 strerror(errno));
            return 0;
        } else if (bytes_read == 0) {
            break;
        }

        total_bytes_read += bytes_read;
    }

    return total_bytes_read;
}

char *read_string(uint64_t addr)
{
    FILE *fp = fdopen(mem_fd, "rb");
    if (fp == NULL) {
        dlog(4, "Cannot open process memory for reading\n");
        return NULL;
    }
    if (fseek(fp, (long int)addr, SEEK_SET)) {
        dlog(4, "Error seeking to %#lx: %s\n", addr,
             strerror(errno));
        return NULL;
    }

    char *buff = NULL;
    size_t buff_sz = 0;
    ssize_t retval = getdelim(&buff, &buff_sz, '\0', fp);
    if (retval == -1) {
        dlog(4, "Error reading string from %#lx: %s\n",
             addr, strerror(errno));
        return NULL;
    }

    // Do not close fp, unless you dup() the file descriptor and
    // fdopen() on the dupe.
    return buff;
}

static void destroy_memory_mapping(memory_mapping *mapping)
{
    /* Note that when a memory mapping is created, the path
     * is a copy of a path string in a mapping group. Do
     * not free here */

    if (mapping == NULL) {
        return;
    }

    if (mapping->perms) {
        free(mapping->perms);
    }

    free(mapping);
}

static void destroy_mapping_group(mapping_group *grp)
{
    GSList *p;

    if (grp == NULL) {
        return;
    }

    if (grp->mappings != NULL) {
        for (p = grp->mappings; p != NULL; p = p->next) {
            destroy_memory_mapping((memory_mapping *)p->data);
        }
        g_slist_free(grp->mappings);
    }

    if (grp->path) {
        free(grp->path);
        grp->path = NULL;
    }

    free(grp);
}

mapping_group *create_mapping_group(memory_mapping *mapping)
{
    mapping_group *grp = malloc(sizeof(mapping_group));

    if (grp == NULL) {
        goto result;
    }

    grp->start = mapping->start;
    grp->end = mapping->end;
    grp->path = mapping->path;
    grp->mappings = g_slist_prepend(NULL, mapping);

result:
    return grp;
}

/* Gets the first mapping matching the specified path. */
memory_mapping *get_mapping(
    const char *pid,
    const char *target_path)
{
    char path[PATH_MAX] = "/proc/";
    memory_mapping *mapping = NULL;
    strncat(path, pid, g_num_digits_pid);
    strncat(path, "/maps", 6);

    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        dlog(4, "Invalid PID: %s\n", pid);
        return NULL;
    }

    char* line = NULL;
    size_t line_sz = 0;
    ssize_t chars_read = 0;

    while ((chars_read = getline(&line, &line_sz, fp)) != -1) {
        if (line[--chars_read] == '\n') {
            line[chars_read] = '\0';
        }
        uint64_t start_address = 0;
        uint64_t end_address = 0;
        uint64_t offset = 0;
        char permissions[5] = "";
        int chars_consumed = 0;
        // the path could contain spaces
        int conversions = sscanf(line, "%lx-%lx %s %lx %*s %*s %n",
                                 &start_address, &end_address, permissions, &offset, &chars_consumed);
        char *file_path = line + chars_consumed;

        if (conversions == 4
                && chars_consumed < chars_read
                && strncmp(target_path, file_path, (size_t)(chars_read - chars_consumed)) == 0) {
            mapping = malloc(sizeof(memory_mapping));
            if (mapping == NULL) {
                goto error;
            }

            mapping->start = start_address;
            mapping->end = end_address;
            mapping->offset = offset;
            mapping->path = strdup(file_path);
            mapping->perms = strdup(permissions);

            if (!mapping->path || !mapping->perms) {
                if (mapping->path) {
                    free(mapping->path);
                }

                destroy_memory_mapping(mapping);
                mapping = NULL;
                goto error;
            }

            goto end;
        }
    }

error:
    dlog(4, "Failed to find mapping for %s", target_path);
end:
    fclose(fp);
    return mapping;
}

/* Given a path of some file mapped into the process memory with a given PID,
 * determine whether at least one page of that file is mapped as executable.
 * TODO: I find this solution a bit inelegant - find something more efficient? */
static int is_executable(const char *pid, const char *path)
{
    int res = -1;
    char proc[PATH_MAX] = "/proc/";
    strncat(proc, pid, g_num_digits_pid);
    strncat(proc, "/maps", 6);

    FILE *fp = fopen(proc, "r");
    if (fp == NULL) {
        dlog(4, "Invalid PID: %s\n", pid);
        return -1;
    }

    char* line = NULL;
    size_t line_sz = 0;
    ssize_t chars_read = 0;

    while ((chars_read = getline(&line, &line_sz, fp)) != -1) {
        if (line[--chars_read] == '\n') {
            line[chars_read] = '\0';
        }

        uint64_t start_address = 0;
        uint64_t end_address = 0;
        uint64_t offset = 0;
        char permissions[5] = "";
        int chars_consumed = 0;
        // the path could contain spaces
        int conversions = sscanf(line, "%lx-%lx %s %lx %*s %*s %n",
                                 &start_address, &end_address, permissions, &offset, &chars_consumed);
        char *file_path = line + chars_consumed;

        if (conversions != 4) {
            dlog(4, "Failed to parse mapping: '%s'\n", line);
            continue;
        }

        if(!strcmp(file_path, path) && strstr(permissions, "x") != NULL) {
            res = 0;
            goto cleanup;
        }
    }

cleanup:
    fclose(fp);
    return res;
}

/* Gets memory mapping groups for file-backed ELF objects. It assumes
 * that memory mappings for an ELF object occur as a block with no
 * mappings for a different ELF object interspersed. */
GSList *get_elf_mapping_groups(const char *pid)
{
    GSList *mapping_groups = NULL, *p;
    char path[PATH_MAX] = "/proc/";
    strncat(path, pid, g_num_digits_pid);
    strncat(path, "/maps", 6);

    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        dlog(4, "Invalid PID: %s\n", pid);
        return NULL;
    }

    char* line = NULL;
    size_t line_sz = 0;
    ssize_t chars_read = 0;
    mapping_group *grp = NULL;

    enum collection_state {NONE, ELF, LDSO};
    enum collection_state state = NONE;
    while ((chars_read = getline(&line, &line_sz, fp)) != -1) {
        memory_mapping *mapping;

        if (line[--chars_read] == '\n') {
            line[chars_read] = '\0';
        }
        uint64_t start_address = 0;
        uint64_t end_address = 0;
        uint64_t offset = 0;
        char permissions[5] = "";
        int chars_consumed = 0;
        // the path could contain spaces
        int conversions = sscanf(line, "%lx-%lx %s %lx %*s %*s %n",
                                 &start_address, &end_address, permissions, &offset, &chars_consumed);
        char *file_path = line + chars_consumed;

        if (conversions != 4) {
            dlog(4, "Failed to parse mapping: '%s'\n", line);
            continue;
        }

        /* /proc/[pid]/maps appends "(deleted)" to the end of the name of the mapping if
         * if the file backing the mapping has been altered. For now, the behavior is to
         * consider this an indication of possible compromise, but some discussion here
         * may be warranted
         */
        if(strstr(file_path, "(deleted)") ==
                file_path + strlen(file_path) - strlen("(deleted)")) {
            dlog(1, "Mapping %s is apriori altered\n", file_path);
            goto error;
        }

get_elf_mapping_groups_parse_mapping:
        switch (state) {
        case NONE:
            // We only care about the start of a file-backed ELF mapping
            if (chars_consumed < chars_read         // There is a path
                    && *file_path != '['                // A real path
                    && !is_executable(pid, file_path)) {
                mapping = malloc(sizeof(memory_mapping));
                if (mapping == NULL) {
                    goto error;
                }

                mapping->start = start_address;
                mapping->end = end_address;
                mapping->offset = offset;
                mapping->path = strdup(file_path);

                if (mapping->path == NULL) {
                    free(mapping);
                    goto error;
                }

                mapping->perms = strdup(permissions);

                if (!mapping->perms) {
                    free(mapping->path);
                    free(mapping);
                    goto error;
                }

                /* There have been several instances of libraries (for instance, ld-2.28 when
                 * compiled with Address Santizer) where a library gets mapped to
                 * multiple distinct, adjacent memory maps. This code deals with this edge
                 * case. However, TODO need a more generalizable way of processing the map
                 * file because I don't know if we can assume that libraries and such
                 * will always be mapped to a contiguous memory location */
                p = mapping_groups;
                while (p != NULL) {
                    grp = (mapping_group *)p->data;
                    if(!strcmp(grp->path, file_path) && grp->end == start_address) {
                        mapping_groups = g_slist_remove(mapping_groups, grp);
                        break;
                    }
                    p = p->next;
                }

                if (p != NULL) {
                    /* A previous group was found */
                    grp->end = end_address;
                    grp->mappings = g_slist_prepend(grp->mappings, mapping);
                } else {
                    /* A previous mapping was not found  */
                    grp = malloc(sizeof(mapping_group));
                    if (grp == NULL) {
                        free(mapping->perms);
                        free(mapping->path);
                        free(mapping);
                        goto error;
                    }

                    grp->start = start_address;
                    grp->end = end_address;
                    grp->path = mapping->path;
                    grp->mappings = g_slist_prepend(NULL, mapping);
                }

                state = ELF;
                char *last_slash = rindex(file_path, '/');
                if (last_slash != NULL) {
                    // This is a loose check, but the LDSO logic just
                    // collects all mappings until the next ld.so
                    // mapping, so there shouldn't be any harm in false
                    // positives.
                    if (strncmp(last_slash + 1, "ld-", 3) == 0) {
                        state = LDSO;
                    }
                }
            }
            break;
        case ELF:
            if (chars_consumed >= chars_read) {
                // This is an anonymous mapping

                if (strncmp(permissions, "rw-p", 4) == 0 &&
                        start_address ==
                        ((memory_mapping *) grp->mappings->data)->end) {
                    // Assume this is an anonymous mapping to finish out
                    // the .bss section of the ELF
                    mapping = malloc(sizeof(memory_mapping));
                    if (mapping == NULL) {
                        goto error;
                    }

                    mapping->start = start_address;
                    mapping->end = end_address;
                    mapping->offset = offset;
                    mapping->path = NULL;
                    mapping->perms = strdup(permissions);
                    if (!mapping->perms) {
                        free(mapping);
                        goto error;
                    }

                    grp->end = end_address;
                    grp->mappings = g_slist_prepend(grp->mappings, mapping);
                }

                grp->mappings = g_slist_reverse(grp->mappings);
                mapping_groups = g_slist_prepend(mapping_groups, grp);
                grp = NULL;
                state = NONE;
            } else if (strcmp(file_path, grp->path) != 0) {
                // A mapping for something else
                grp->mappings = g_slist_reverse(grp->mappings);
                mapping_groups = g_slist_prepend(mapping_groups, grp);
                grp = NULL;
                state = NONE;
                goto get_elf_mapping_groups_parse_mapping;
            } else {
                // More of the same ELF object
                mapping = malloc(sizeof(memory_mapping));
                if (mapping == NULL) {
                    goto error;
                }

                mapping->start = start_address;
                mapping->end = end_address;
                mapping->offset = offset;
                mapping->path = grp->path;
                mapping->perms = strdup(permissions);
                if (!mapping->perms) {
                    free(mapping);
                    goto error;
                }

                grp->end = end_address;
                grp->mappings = g_slist_prepend(grp->mappings, mapping);
            }
            break;
        case LDSO:
            // ld.so often has anonymous mappings or mappings for other
            // files in its space, but we don't care about them, so pass
            // over them and only grab ld.so's mappings.
            if (chars_consumed < chars_read &&
                    strcmp(file_path, grp->path) == 0) {
                // At this point it's no different than any other ELF
                mapping = malloc(sizeof(memory_mapping));
                if(!mapping) {
                    goto error;
                }

                mapping->start = start_address;
                mapping->end = end_address;
                mapping->offset = offset;
                mapping->path = grp->path;
                mapping->perms = strdup(permissions);
                if (!mapping->perms) {
                    free(mapping);
                    goto error;
                }

                grp->end = end_address;
                grp->mappings = g_slist_prepend(grp->mappings, mapping);
                state = ELF;
            }
            break;
        default:
            err(EXIT_FAILURE, "You have achieved the impossible");
            break;
        }
    }

    // In case the last mapping was part of a group; although,
    // [vsyscall] might always be last
    if (grp != NULL) {
        grp->mappings = g_slist_reverse(grp->mappings);
        mapping_groups = g_slist_prepend(mapping_groups, grp);
    }

    fclose(fp);

    return g_slist_reverse(mapping_groups);

error:
    /* Clean up the mapping_groups struct as required */
    if (mapping_groups != NULL) {
        for (p = mapping_groups; p != NULL; p = p->next) {
            destroy_mapping_group((mapping_group *)p->data);
        }
        g_slist_free(mapping_groups);
    }

    /* Will free up group if it is allocated */
    destroy_mapping_group(grp);

    fclose(fp);

    return NULL;
}

void print_mapping_groups(GSList *mapping_groups)
{
    GSList *p;
    puts("ELF memory mapping groups:");
    for (p = mapping_groups; p != NULL; p = p->next) {
        mapping_group *grp = p->data;
        printf("  %#016lx - %#016lx : %s\n", grp->start, grp->end,
               grp->path);
        GSList *mp;
        for (mp = grp->mappings; mp != NULL; mp = mp->next) {
            memory_mapping *mapping = mp->data;
            printf("    %#016lx - %#016lx %s %#08lx %s\n",
                   mapping->start,
                   mapping->end,
                   mapping->perms,
                   mapping->offset,
                   mapping->path);
        }
    }
}

/* Produces a file_mapping_buffer for the provided mapping group. The
 * buffer will be sized according to the group parameters, but only
 * readable mappings will be memcopied in at the appropriate offsets.
 */
file_mapping_buffer *create_file_mapping_buffer(
    mapping_group *grp)
{
    size_t sz = grp->end - grp->start;

    // calloc so unused parts will be zeroed and hopefully
    // an invalid read will be obvious
    void *buf = calloc(1, sz);
    if (buf == NULL) {
        return NULL;
    }

    uint64_t offset = 0;
    GSList *p;
    for (p = grp->mappings; p != NULL; p = p->next) {
        memory_mapping *m = p->data;
        if (strchr(m->perms, 'r') != NULL) {
            offset = m->start - grp->start;
            if(read_into(buf + offset, m->start, m->end - m->start) < m->end - m->start) {
                dlog(4, "Unable to read memory mapping properly\n");
                goto error;
            };
        }
    }
    file_mapping_buffer *mb = malloc(sizeof(file_mapping_buffer));
    if (mb == NULL) {
        goto error;
    }

    mb->buf = buf;
    mb->path = grp->path;
    mb->start = grp->start;
    mb->sz = sz;

    return mb;

error:
    free(buf);
    return NULL;
}

/* Copy the readable memory for each mapping in a group into a
 * contiguous buffer. The mappings probably have gaps between each
 * other, which will be preserved in the buffer as a zeroed out region.
 */
GSList *get_elf_buffers(GSList *elf_mapping_groups)
{
    GSList *p_grp;
    GSList *buffs = NULL;

    for (p_grp = elf_mapping_groups; p_grp != NULL;
            p_grp = p_grp->next) {
        mapping_group *grp = p_grp->data;
        buffs = g_slist_prepend(buffs,
                                create_file_mapping_buffer(grp));
    }

    return g_slist_reverse(buffs);
}
