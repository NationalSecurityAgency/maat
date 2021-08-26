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
 * socket.c: File for the socket based
 * communications in between the attester and
 * appraiser.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "inet-socket.h"
#include <glib.h>
#include <limits.h>
#include <util/maat-io.h>
#include <util/util.h>

int
setup_listen_server(char *addr, uint16_t portnum)
{
    struct sockaddr_in serv;
    int reuse = 1;
    int con_socket;

    memset(&serv,0,sizeof(serv));
    serv.sin_family = AF_INET;

    if(inet_pton(serv.sin_family, addr, &(serv.sin_addr)) != 1) {
        dperror("Invalid address\n");
        return -1;
    }

    serv.sin_port = htons(portnum);
    con_socket = socket(AF_INET, SOCK_STREAM,0);
    if(con_socket == -1) {
        dperror("error in setting up socket\n");
        return -1;
    }

    if(setsockopt(con_socket, SOL_SOCKET, SO_REUSEADDR,(char *)&reuse, (socklen_t)sizeof(reuse))<0) {
        dperror("Setting SO_REUSEADDR error\n");
        close(con_socket);
        return -1;
    }
    if(bind(con_socket,(struct sockaddr *)&serv, (socklen_t)sizeof(struct sockaddr))==-1) {
        dperror("error binding socket\n");
        close(con_socket);
        return -1;
    }
    if(listen(con_socket,1)==-1) {
        dperror("error on listen\n");
        close(con_socket);
        return -1;
    }
    //con_socket = accept(con_socket,(struct sockaddr *)&dest, &socksize);
    return con_socket;
}

int
connect_to_server(char* ip, uint16_t portnum)
{
    struct sockaddr_in dest;
    int my_socket = socket(AF_INET,SOCK_STREAM,0);
    int max_attempts = 10;
    int con_attempts = 0;
    int retval;
    int res;
    if(my_socket < 0) {
        fprintf(stderr, "Failed to create socket\n");
        return -1;
    }

    memset(&dest,0,sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ip);
    if(dest.sin_addr.s_addr == INADDR_NONE) { //INADDR_NONE = -1
        close(my_socket);
        return -1;
    }

    dest.sin_port = htons(portnum);
    while(con_attempts < max_attempts) {
        retval =  connect(my_socket, (struct sockaddr *)&dest, (socklen_t)sizeof(struct sockaddr));
        if(retval == 0) {
            break;
        }
        con_attempts++;
        sleep(1);
    }
    if(retval < 0) {
        close(my_socket);
        return -1;
    }


    if((res = maat_io_channel_new(my_socket)) < 0) {
        close(my_socket);
    }

    return res;
}
