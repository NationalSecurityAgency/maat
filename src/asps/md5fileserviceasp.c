/*
 * Copyright 2020 United States Government
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
 * This ASP is an example of a service asp that hashes the data sent in.
 * Uses md5 hash algorithm
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <util/util.h>
#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>
#include <measurement/md5_measurement_type.h>
#include <measurement/filename_measurement_type.h>
#include <address_space/file_address_space.h>
#include <address_space/simple_file.h>

#include <openssl/md5.h>
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <md5fileserviceasp.h>

static int set_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        return -errno;
    }
    flags &= ~O_NONBLOCK;

    return fcntl(fd, F_SETFL, flags);
};

int asp_init(int argc, char *argv[])
{
    int ret_val = 0;
    asp_logdebug("Initialized hashfileservice ASP\n");

    if( (ret_val = register_measurement_type(&md5hash_measurement_type)) )
        return ret_val;
    if( (ret_val = register_measurement_type(&filename_measurement_type)) )
        return ret_val;
    if( (ret_val = register_address_space(&file_addr_space)) )
        return ret_val;
    if( (ret_val = register_address_space(&simple_file_address_space)) )
        return ret_val;

    return 0;
}

int asp_exit(int status)
{
    asp_logdebug("Exiting hashfileservice ASP\n");
    return 0;
}

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph;
    node_id_t node_id;

    address *address	= NULL;
    char *path		= NULL;
    int fd		=-1;
    char *buffer	= NULL; /* contents of the file */
    md5hash_measurement_data *md5hash_data = NULL;

    int ret_val	= 0;
    int filelen = 0;


    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    asp_logdebug("hashfile: nodeid  "ID_FMT"\n", node_id);

    if( (address = measurement_node_get_address(graph, node_id)) == NULL) {
        ret_val = -EIO;
        asp_logerror("Failed to get address of file to hash: %s\n", strerror(errno));
        goto error;
    }

    if(address->space == &file_addr_space) {
        path = ((file_addr*)address)->fullpath_file_name;
    } else if(address->space == &simple_file_address_space) {
        path = ((simple_file_address *)address)->filename;
    }
    if(path == NULL) {
        asp_logerror("File to hash has unexpected address type %s\n", address->space->name);
        ret_val = -EINVAL;
        goto error;
    }

    asp_logdebug("Hashing file: %s\n", path);

    // open file and read contents
    // Open file
    fd = open(path, O_RDONLY|O_NONBLOCK);
    struct stat st;

    if(fd < 0) {
        ret_val = -errno;
        asp_logerror("failed to open file \"%s\": %s\n", path, strerror(errno));
        goto error;
    }

    if (set_blocking(fd) != 0) {
        ret_val = -errno;
        asp_logerror("failed to set file to blocking after open \"%s\": %s\n",
                     path, strerror(errno));
        goto error;
    }

    if(fstat(fd, &st) != 0) {
        ret_val = -errno;
        asp_logerror("failed to stat file \"%s\": %s\n", path, strerror(errno));
        goto error;
    }

    if(!(S_ISREG(st.st_mode))) {
        ret_val = -EINVAL;
        asp_logwarn("Not hashing non-regular file \"%s\"\n", path);
        goto error;
    }

    filelen = st.st_size;

    //Allocate memory
    buffer=(char *)malloc(filelen);
    if (!buffer) {
        asp_logerror("Failed to allocate buffer to hold file contents.\n");
        ret_val = -ENOMEM;
        goto error;
    }

    asp_logdebug("Alloced buffer of size %d\n", filelen);
    //Read file contents into buffer
    if(read(fd, buffer, filelen) < filelen) {
        ret_val = -errno;
        asp_logerror("Failed to read file %s : %s\n", path, strerror(errno));
        goto error;
    }

    asp_logdebug("Read file %s. Hashing...\n", path);
    close(fd);
    fd = -1;

    // create hash measurement data
    md5hash_data = (md5hash_measurement_data*)md5hash_measurement_type.alloc_data();
    if (!md5hash_data) {
        asp_logerror("Failed to allocate hash measurement data\n");
        ret_val = -ENOMEM;
        goto error;
    }


    // Hash it
    MD5((unsigned char*)buffer, filelen, md5hash_data->md5_hash);

    if(__libmaat_debug_level >= 2) {
        char hash_ascii_buf[MD5HASH_LEN*2 + 1];
        int i;
        for(i=0; i<MD5HASH_LEN; i++) {
            sprintf(&hash_ascii_buf[2*i], "%02hhx", md5hash_data->md5_hash[i]);
        }
        asp_loginfo("File %s md5 hash is %s\n", path, hash_ascii_buf);
    }

    free(buffer);
    buffer = NULL;

    asp_logdebug("Attaching hash measurement: %s, to the graph\n", path);

    // attach measurement data to node
    if(measurement_node_add_rawdata(graph, node_id, &md5hash_data->meas_data) < 0) {
        asp_logerror("Failed to add hash data to measurement node.\n");
        ret_val = -EIO;
        goto error;
    }

    free_measurement_data(&md5hash_data->meas_data);
    free_address(address);
    address = NULL;
    unmap_measurement_graph(graph);

    return 0;  // success

error:
    free_address(address);
    free_measurement_data(&md5hash_data->meas_data);
    free(buffer);
    if(fd >= 0) {
        close(fd);
    }
    unmap_measurement_graph(graph);
    return ret_val;
}


