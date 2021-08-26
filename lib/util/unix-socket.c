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
 * unix-socket.c: File for the unix socket based
 * communications in between the attester and
 * appraiser.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include "unix-socket.h"
#include <glib.h>
#include <limits.h>
#include <util/maat-io.h>
#include <util/util.h>


int open_unix_client(char *path)
{
    struct sockaddr_un addr;
    int fd;
    int chan = -1;

    if(path == NULL) {
        dlog(2,"open_unix_client() path is NULL\n");
        goto err_null_path;
    }

    if((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0) {
        dlog(2,"socket() failed: %d\n", errno);
        goto err_sock;
    }

    memset(&addr, 0, sizeof(addr));
    //addr.sun_len = sizeof(struct sockaddr_un);
    addr.sun_family = AF_LOCAL;
    //XXX: Some implementations had
    //assert(strlen(path) < 108); //per UNIX(7), UNIX_PATH_MAX == 108
    //memcpy(addr.sun_path, path, strlen(path)+1);
    //instead of strncpy below.
    strncpy(addr.sun_path, path, 103);

    int con_attempts = 0;
    int retval = 0;
    while (con_attempts < 5) {
        retval = connect(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr) );
        if (retval == 0) {
            break;
        }
        con_attempts++;
        usleep(10000);
    }

    if(retval < 0) {
        dlog(2,"connect() failed: %s\n", strerror(errno));
        goto err_connect;
    }

    if(fd >= 0) {
        if((chan = maat_io_channel_new(fd)) < 0) {
            dlog(2, "maat_io_channel_new failed\n");
            goto err_channel;
        }
    }
    return chan;

err_channel:
err_connect:
    close(fd);
err_sock:
err_null_path:
    return -1;
}

int setup_local_listen_server(char *path)
{
    struct sockaddr_un serv;
    int reuse = 1;
    int con_socket;

    memset(&serv,0,sizeof(serv));
    serv.sun_family = AF_LOCAL;

    if(strlen(path) > sizeof(serv.sun_path)-1) {
        perror("error: requested socket path is too long\n");
        return -1;
    }
    strncpy(serv.sun_path, path, sizeof(serv.sun_path)-1);

    con_socket = socket(AF_LOCAL, SOCK_STREAM,0);
    if(con_socket == -1) {
        printf("error in setting up socket\n");
        return -1;
    }
    if(setsockopt(con_socket, SOL_SOCKET, SO_REUSEADDR,&reuse, (socklen_t)sizeof(int))<0) {
        perror("Setting SO_REUSEADDR error\n");
        close(con_socket);
        return -1;
    }
    if(bind(con_socket,(struct sockaddr *)&serv, (socklen_t)sizeof(serv))==-1) {
        perror("error binding socket\n");
        close(con_socket);
        return -1;
    }
    if(listen(con_socket,1)==-1) {
        perror("error on listen\n");
        close(con_socket);
        return -1;
    }
    return con_socket;
}

