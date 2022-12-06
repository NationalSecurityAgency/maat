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
 * Socket.h: Header file for the socket based
 * communications in between the attester and
 * appraiser.
 */
#ifndef __MAAT_UTIL_INET_SOCKET_H__
#define __MAAT_UTIL_INET_SOCKET_H__

#include <glib.h>

/**
 * Create a server to listen on
 * a select address and port number
 * for incoming communication.
 */
int setup_listen_server(char *addr, uint16_t portnum);
/**
 * Tries to connect to a server that
 * is listening on the given port
 * number at the  * given IP address.
 */
int connect_to_server(char *ip, uint16_t portnum);
/**
 * Send data through a socket of the
 * specified size.
 */
int socket_send(int sockfd, int data_size, char *data);
/**
 * Listen for any sent data
 * through a socket.
 */
int socket_recv(int sockfd, int data_size, char *data);
#endif
