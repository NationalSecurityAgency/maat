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

/*! \file
 * This ASP takes a process pid as input and finds and collects data on its
 * /proc/[pid]/maps file
 * The asp_measure function creates a node for the pid's maps file
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/sha.h>

#include <util/util.h>
#include <asp/asp-api.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>
#include <maat-basetypes.h>
#include <graph/graph-core.h>

#define ASP_NAME        "memorymappingasp"

static int set_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        return -errno;
    }
    flags &= ~O_NONBLOCK;

    return fcntl(fd, F_SETFL, flags);
};


map_entry *chunk_mapping_line_data(char *raw_line)
{
    map_entry *ret = NULL;
    uint64_t va_start, va_end;
    uint8_t r = 1;
    uint8_t w = 1;
    uint8_t x = 1;
    uint8_t p = 1;
    uint64_t offset, dev_major, dev_minor, inode;
    char path[1024];
    size_t pathlen;

    char *tmp;

    tmp = strtok(raw_line, "-"); //tmp = start address
    sscanf(tmp, "%"SCNx64, &va_start);

    tmp = strtok(NULL, " "); //tmp = end address
    sscanf(tmp, "%"SCNx64, &va_end);

    tmp = strtok(NULL, " "); //tmp = perms
    if (strlen(tmp) != 4) {
        dlog(0, "Error: Invalid perms\n");
        return ret;
    }
    if (tmp[0] == '-')  r = 0;
    if (tmp[1] == '-')  w = 0;
    if (tmp[2] == '-')  x = 0;
    if (tmp[3] == '-')  p = 0;

    tmp = strtok(NULL, " "); //tmp = offset
    sscanf(tmp, "%"SCNx64, &offset);

    tmp = strtok(NULL, ":"); //tmp = dev major
    sscanf(tmp, "%"SCNx64, &dev_major);

    tmp = strtok(NULL, " "); //tmp = dev minor
    sscanf(tmp, "%"SCNx64, &dev_minor);

    tmp = strtok(NULL, " "); //tmp = inode
    sscanf(tmp, "%"SCNx64, &inode);

    //TODO: right way to handle empties and pathlen?
    tmp = strtok(NULL, " \n"); //tmp = path
    if (tmp == NULL) {
        path[0] = '\0';
    } else if (strlen(tmp) > 1000) {
        dlog(0, "path is too long\n");
        path[0] = '\0';
    } else {
        sscanf(tmp, "%1000s", path);
    }
    pathlen = strlen(path) + 1;
    ret = mk_map_entry(va_start, va_end, r, w, x, p, offset, dev_major, dev_minor, inode, pathlen, path);
    return ret;
}

int asp_init(int argc, char *argv[])
{
    int ret_val = 0;
    asp_loginfo("Initialized memorymapping ASP\n");

    // register all types used
    if( (ret_val = register_address_space(&pid_address_space)) ) {
        return ret_val;
    }
    if( (ret_val = register_measurement_type(&mappings_measurement_type)) ) {
        return ret_val;
    }
    if( (ret_val = register_target_type(&process_target_type)) ) {
        return ret_val;
    }

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting memorymapping ASP\n");
    return ASP_APB_SUCCESS;
}

static int add_memory_segment_node(measurement_graph *graph, node_id_t process_node,
                                   uint64_t pid, map_entry *entry, node_id_t *out)
{
    measurement_variable var;
    pid_mem_range *pmr_addr = NULL;
    node_id_t tmpnode = INVALID_NODE_ID;
    edge_id_t edge;
    int rc = 0;

    var.type = &process_target_type;
    var.address = alloc_address(&pid_mem_range_space);

    if(var.address == NULL) {
        rc = -ENOMEM;
        goto out;
    }

    pmr_addr = container_of(var.address, pid_mem_range, a);
    if(pid > UINT_MAX) {
        rc = -EINVAL;
        goto out;
    }

    pmr_addr->pid = (pid_t)pid;
    pmr_addr->offset = entry->va_start;
    pmr_addr->size = entry->va_end - entry->va_start;

    if((rc = measurement_graph_add_node(graph, &var, NULL, &tmpnode)) < 0) {
        goto out;
    }
    *out = tmpnode;

    if((rc = measurement_graph_add_edge(graph, process_node, "mappings.segments",
                                        tmpnode, &edge)) < 0) {
        asp_logwarn("Failed to add mappings.segments edge\n");
    }

    if(entry->r) {
        if((rc = measurement_graph_add_edge(graph, process_node, "mappings.readable_segments",
                                            tmpnode, &edge)) < 0) {
            asp_logwarn("Failed to add mappings.readable_segments edge\n");
        }
    }

    if(entry->w) {
        if((rc = measurement_graph_add_edge(graph, process_node, "mappings.writable_segments",
                                            tmpnode, &edge)) < 0) {
            asp_logwarn("Failed to add mappings.writable_segments edge\n");
        }
    }
    if(entry->x) {
        if((rc = measurement_graph_add_edge(graph, process_node, "mappings.executable_segments",
                                            tmpnode, &edge)) < 0) {
            asp_logwarn("Failed to add mappings.executable_segments edge\n");
        }
    }
    if(entry->p) {
        if((rc = measurement_graph_add_edge(graph, process_node, "mappings.private_segments",
                                            tmpnode, &edge)) < 0) {
            asp_logwarn("Failed to add mappings.private_segments edge\n");
        }
    }

    rc = 0;
out:
    free_address(var.address);
    return rc;
}

static int add_file_region_node(measurement_graph *graph, node_id_t process_node,
                                node_id_t memory_segment_node, map_entry *entry,
                                node_id_t *out)
{
    measurement_variable var;
    file_region_address *fr_addr = NULL;
    node_id_t tmpnode = INVALID_NODE_ID;
    edge_id_t edge = INVALID_EDGE_ID;
    int rc = 0;
    GChecksum *csum = NULL;
    size_t csum_size;
    ssize_t result;

    var.type = &file_target_type;
    var.address = alloc_address(&file_region_address_space);
    if(var.address == NULL) {
        rc = -ENOMEM;
        goto out;
    }

    fr_addr		= container_of(var.address, file_region_address, a);
    fr_addr->path	= strndup(entry->path, entry->pathlen);
    fr_addr->offset	= entry->offset;
    fr_addr->sz		= entry->va_end - entry->va_start;

    if (fr_addr->sz > SSIZE_MAX) {
        asp_logwarn("File region size %zu too large to use with checksum library\n", fr_addr->sz);
        goto out;
    }

    if((rc = measurement_graph_add_node(graph, &var, NULL, &tmpnode)) < 0) {
        asp_logwarn("Failed to add file_region node process node: %d\n", rc);
        goto out;
    }
    *out = tmpnode;

    if((rc = measurement_graph_add_edge(graph, process_node, "mappings.file_regions",
                                        tmpnode, &edge)) < 0) {
        asp_logwarn("Failed to add mappings.file_regions edge to process node\n");
    }
    if((rc = measurement_graph_add_edge(graph, memory_segment_node, "mappings.file_regions_mapped",
                                        tmpnode, &edge)) < 0) {
        asp_logwarn("Failed to add mappings.file_regions edge to memory region node\n");
    }

    if (entry->x && measurement_node_has_data(graph, tmpnode,
            &sha1hash_measurement_type) == 0) {
        measurement_data *data = NULL;
        sha256_measurement_data *sha_data = NULL;
        int fd;
        uint8_t *buf;

        fd = open(fr_addr->path, O_RDONLY|O_NONBLOCK);
        if (fd < 0) {
            dlog(3, "Failed to open file for reading\n");
            goto out;
        }

        /*
         * Magic needed to avoid files blocking on open when they're opened
         * by another process as O_EXCL.
         */
        if (set_blocking(fd) != 0) {
            rc = -errno;
            asp_logerror("failed to set file to blocking after open \"%s\": %s\n",
                         fr_addr->path, strerror(errno));
            close(fd);
            goto out;
        }

        // Cannot check bounds of off_t because no MIN or MAX macros for off_t are defined
        if (lseek(fd, (off_t)fr_addr->offset, SEEK_SET) < 0) {
            dlog(0, "Failed to seek in %s to offset %lu\n", fr_addr->path,
                 fr_addr->offset);
            close(fd);
            goto out;
        }

        buf = malloc(fr_addr->sz);
        if (!buf) {
            dlog(0, "Failed to allocate buffer of size %lu\n", fr_addr->sz);
            close(fd);
            goto out;
        }

        result = read(fd, buf, fr_addr->sz);
        // Cast is justified because of previous bounds check
        if (result < 0 || (size_t)result != fr_addr->sz) {
            dlog(0, "Failed to read all of file into buffer: rc = %zd, sz = %lu\n",
                 result, fr_addr->sz);
            free(buf);
            close(fd);
            goto out;
        }
        close(fd);

        data = alloc_measurement_data(&sha256_measurement_type);
        if (!data) {
            dlog(0, "Error allocating measuremnt data\n");
            free(buf);
            goto out;
        }
        sha_data = container_of(data, sha256_measurement_data, meas_data);

        csum = g_checksum_new(G_CHECKSUM_SHA256);
        // Cast is justified because of previous bounds check
        g_checksum_update(csum, (unsigned char *)buf, (ssize_t)fr_addr->sz);
        g_checksum_get_digest(csum, sha_data->sha256_hash, &csum_size);
        g_checksum_free(csum);

        if (csum_size != SHA256_TYPE_LEN) {
            asp_logwarn("checksum_size (%zd) != expected (%d)\n", csum_size,
                        SHA256_TYPE_LEN);
        }

        free(buf);

        if(measurement_node_add_rawdata(graph, tmpnode, &sha_data->meas_data) < 0) {
            asp_logerror("Failed to add hash data to measurement node.\n");
            rc = -EIO;
            goto out;
        }

        asp_loginfo("Added hash of file region to node\n");
        free_measurement_data(&sha_data->meas_data);
    }
out:
    free_address(var.address);
    return rc;
}

static int add_file_node(measurement_graph *graph, node_id_t process_node,
                         node_id_t memory_segment_node, node_id_t file_region_node,
                         map_entry *entry, node_id_t *out)
{
    measurement_variable var;
    simple_file_address *sf_addr = NULL;
    node_id_t tmpnode = INVALID_NODE_ID;
    edge_id_t edge = INVALID_EDGE_ID;
    int rc = 0;

    var.type = &file_target_type;
    var.address = alloc_address(&simple_file_address_space);
    if(var.address == NULL) {
        rc = -ENOMEM;
        goto out;
    }

    sf_addr		= container_of(var.address, simple_file_address, a);
    sf_addr->filename	= strndup(entry->path, entry->pathlen);

    if((rc = measurement_graph_add_node(graph, &var, NULL, &tmpnode)) < 0) {
        goto out;
    }
    *out = tmpnode;

    if((rc = measurement_graph_add_edge(graph, process_node, "mappings.files",
                                        tmpnode, &edge)) < 0) {
        asp_logwarn("Failed to add mappings.files edge to process node\n");
    }

    if (path_is_reg(sf_addr->filename)) {
        if((rc = measurement_graph_add_edge(graph, process_node, "mappings.reg_files",
                                            tmpnode, &edge)) < 0) {
            asp_logwarn("Failed to add mappings.files edge to process node\n");
        }
    }
    if((rc = measurement_graph_add_edge(graph, memory_segment_node, "mappings.files",
                                        tmpnode, &edge)) < 0) {
        asp_logwarn("Failed to add mappings.files edge to memory region node\n");
    }
    if((rc = measurement_graph_add_edge(graph, tmpnode, "mappings.mapped_regions",
                                        file_region_node, &edge)) < 0) {
        asp_logwarn("Failed to add mappings.mapped_regions edge to file node\n");
    }
out:
    free_address(var.address);
    return rc;
}

int asp_measure(int argc, char *argv[])
{
    asp_loginfo("In memorymapping ASP\n");

    int ret_val = 0;

    address *address = NULL;
    FILE *fp = NULL;
    char *line = NULL;
    map_entry *entry = NULL;
    struct pid_address *pa = NULL;

    char strbuf[1024];
    size_t len = 0;

    measurement_graph *graph = NULL;
    node_id_t process_node;

    if((argc < 3) ||
            ((process_node = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }


    if((address = measurement_node_get_address(graph, process_node)) == NULL) {
        asp_logerror("failed to get address of node "ID_FMT"\n", process_node);
        unmap_measurement_graph(graph);
        return -EINVAL;
    }

    if(address->space == &pid_address_space) {
        pa = (struct pid_address *)address;
    }

    if(pa == NULL) {
        asp_logerror("memmap asp was given a %x address (requires a pid)",
                     address->space->magic);
        ret_val =  ASP_APB_ERROR_ADDRESSSPACEORTYPE;
        goto error;
    }
    if (pa->pid == UINT32_MAX) {
        dlog(0, "Invalid pid\n");
        goto error;
    }

    asp_loginfo("Will look at pid %d\n", pa->pid);
    sprintf(strbuf, "/proc/%d/maps",pa->pid);

    fp = fopen(strbuf, "r");
    if (fp == NULL) {
        dlog(0, "file open error on %s: %s\n", strbuf, strerror(errno));
        ret_val = ASP_APB_ERROR_GENERIC;
        goto error;
    }

    while(getline(&line, &len, fp ) != -1) {
        entry = chunk_mapping_line_data(line);
        if (!entry) {
            dlog(0, "chunk_mapping_line_data returned NULL\n");
            ret_val = ASP_APB_ERROR_GENERIC;
            goto error;
        }

        asp_logwarn("file: %s (%zd)\n", entry->path, entry->pathlen);
        node_id_t mem_segment_node = INVALID_NODE_ID;
        node_id_t file_region_node = INVALID_NODE_ID;
        node_id_t file_node        = INVALID_NODE_ID;;

        if(add_memory_segment_node(graph, process_node, pa->pid, entry,
                                   &mem_segment_node) < 0) {
            asp_logwarn("Failed to add node for memory segment\n");
            goto next_entry;
        }

        if (entry->pathlen > 1) {
            if(add_file_region_node(graph, process_node, mem_segment_node, entry,
                                    &file_region_node) < 0) {
                asp_logwarn("Failed to add file region node\n");
                goto next_entry;
            }

            if(add_file_node(graph, process_node, mem_segment_node,
                             file_region_node, entry, &file_node) < 0) {
                asp_logwarn("Failed to file node\n");
                goto next_entry;
            }
        }

next_entry:
        free_map_entry(entry);
    }
    fclose(fp);
    fp = NULL;

    free_address(&pa->a);
    unmap_measurement_graph(graph);
    return ASP_APB_SUCCESS;

error:
    free_address(&pa->a);
    unmap_measurement_graph(graph);
    if(fp)
        fclose(fp);
    return ret_val;
}


