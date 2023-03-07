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
 * This asp collects evidence from IoT devices.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>

#include <util/util.h>

#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <common/asp-errno.h>
#include <measurement_spec/find_types.h>
#include <address_space/simple_file.h>
#include <address_space/file_address_space.h>
#include <maat-basetypes.h>

#include <libiota.h>
#include <libiota_helper.h>
#include <iota_certs.h>

#ifndef ASP_NAME
#define ASP_NAME "IOT_UART"
#endif

uint32_t read_size = 3000;
#define MAX_READS 500

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{

    printf("+--------------------------------------------------------------+\n");
    printf("|            Maat-Libiota Demo: Requester-Appraiser            |\n");
    printf("+--------------------------------------------------------------+\n");

    printf("\nIoT_UART: Initializing IoT UART ASP...\r\n");

    asp_loginfo("Initializing IoT UART ASP\n");
    register_types();

    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    asp_loginfo("Exiting IoT UART ASP\n");
    return ASP_APB_SUCCESS;
}


/* much of this adapted from
 * https://stackoverflow.com/questions/6947413/how-to-open-read-and-write-from-serial-port-in-c
 */
int set_interface_attribs (int fd, speed_t speed, tcflag_t parity, int ctrl)
{
    struct termios tty;
    memset (&tty, 0, sizeof tty);
    if (tcgetattr (fd, &tty) != 0) {
        printf("\nIoT_UART: Error %d from tcgetattr...\n", errno);
        return -1;
    }

    cfsetospeed (&tty, speed);
    cfsetispeed (&tty, speed);

    tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;     // 8-bit chars
    // disable IGNBRK for mismatched speed tests; otherwise receive break
    // as \000 chars
    tty.c_iflag &= ~IGNBRK;         // disable break processing
    tty.c_lflag = 0;                // no signaling chars, no echo,
    // no canonical processing
    tty.c_oflag = 0;                // no remapping, no delays
    tty.c_cc[VMIN]  = 0;            // read doesn't block
    tty.c_cc[VTIME] = 5;            // 0.5 seconds read timeout

    if (ctrl)
        tty.c_iflag &= (IXON | IXOFF | IXANY); // disable xon/xoff ctrl
    else
        tty.c_iflag &= ~(IXON | IXOFF | IXANY); // enable xon/xoff ctrl

    tty.c_cflag |= (CLOCAL | CREAD);// modem controls, // enable reading
    tty.c_cflag &= ~(PARENB | PARODD);   // shut off parity
    tty.c_cflag |= parity;
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CRTSCTS;

    if (tcsetattr (fd, TCSANOW, &tty) != 0) {
        printf("\nIoT_UART: Error %d from UART tcsetattr...\n", errno);
        return -1;
    }
    return 0;
}

void set_blocking (int fd, int should_block) //0 - non blocking
{
    struct termios tty;
    memset (&tty, 0, sizeof tty);
    if (tcgetattr (fd, &tty) != 0) {
        printf("\nIoT_UART: Error %d from UART tggetattr...\n", errno);
    }

    tty.c_cc[VMIN]  = (cc_t)should_block ? 1 : 0;
    tty.c_cc[VTIME] = (cc_t)5;            // 0.5 seconds read timeout

    if (tcsetattr (fd, TCSANOW, &tty) != 0)
        printf("\nIoT_UART: Error %d setting UART term attributes...\n", errno);
}

int uart_iota_meas(char* uart_filename, unsigned char **iota_meas, uint32_t *iota_meas_len,
                   unsigned char* req_ser, int req_ser_ln)     //iota_meas is the response //iota_meas_len is the size of the received buffer
{
    int fd = open (uart_filename, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        printf("\nIoT_UART: Error %d opening %s, %s...\n", errno, uart_filename, strerror(errno));
        return -1;
    }

    printf ("\nIoT_UART: Sending IoTA Request to Measurer device...\n");

    set_blocking (fd, 0);
    set_interface_attribs (fd, B115200, 0, 0);

    int bytes_sent = write (fd, req_ser, req_ser_ln);  //send request for measurement

    if (bytes_sent != req_ser_ln) {
        printf("\nIoT_UART: Failed to send full request over UART...\n");
        return -1;
    }

    set_blocking (fd, 0);
    set_interface_attribs (fd, B115200, 0, 1);

    printf ("\nIoT_UART: Bytes Sent -> %d\n", req_ser_ln);

    printf ("\nIoT_UART: Waiting for IoTA Response from Measurer device...\n");

    uint32_t n_read = 0;
    unsigned char buf[4096] = {0};
    int attempts = 0;
    int flag = 0;
    while (n_read < read_size) {
        sleep(1);
        int this_read = read(fd, &(buf[n_read]), read_size - n_read);
        n_read += this_read;

        if (n_read > 2 && flag == 0) {
            uint32_t *p = buf;
            *p++;
            uint32_t size = *p++;
            read_size = size;
            flag = 1;
        }

        attempts++;
        if (attempts > MAX_READS) {
            printf("\nIoT_UART: UART device did not write (or receive) expected data after %d attempts...\n",
                   MAX_READS);
            close(fd);
            return -1;
        }
    }
    if (n_read != read_size) {
        printf ("\nIoT_UART: Programmer error - this shouldn't happen...\n");
        close (fd);
        return -1;
    }

    printf("\nIoT_UART: Bytes Received -> %d\n", n_read);

    *iota_meas = malloc(n_read);
    if (*iota_meas==NULL) {
        close (fd);
        return -1;
    }
    close (fd);
    memcpy(*iota_meas, buf, n_read);
    *iota_meas_len = n_read;
    return 0;
}

iota_meas_func meas_funcs[] = {
    {
        .type = 0,
        .name = "",
        .func = NULL,
        .free_func = NULL
    }
};

int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph = NULL;
    node_id_t node_id;
    int ret;
    address *addr;
    char* uart_filename = NULL;
    iota iota_inst_req;
    iota iota_inst_resp;
    uint8_t nonce[64];
    uint8_t c;
    iota_msg *req;
    unsigned char* req_ser;
    int req_ser_ln;

    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    addr = measurement_node_get_address(graph, node_id);
    if (!addr) {
        asp_logerror("Couldn't get UART filename address of device to measure\n");
        return -EINVAL;
    }

    uart_filename = simple_file_address_space.human_readable(addr);
    printf("\nIoT_UART: Measuring device connected to %s...\n", uart_filename);

    //create request
    if ((ret = iota_init(&iota_inst_req, meas_funcs, 0,
                         (uint8_t*)tz_pubcert_pem, tz_pubcert_pem_sz)) != IOTA_OK) {
        printf("\nIoTA Error: failed to initialize libiota instance...\n");
        return -1;
    }

    printf("\nIoT_UART: IoTA Instance Initialized...\r\n");

    for (c = 0; c < sizeof(nonce); c++) {
        nonce[c] = c;
    }

    //IOTA_SIGNED_FLAG | IOTA_ENCRYPTED_FLAG

    if ((ret = iota_req_init(&iota_inst_req, &req, IOTA_SIGNED_FLAG | IOTA_ENCRYPTED_FLAG, IOTA_ACTION_MEAS, 0, NULL, 0,
                             nonce, sizeof(nonce), (uint8_t*)tz_pubcert_pem, tz_pubcert_pem_sz)) != IOTA_OK) {
        printf("\nIoT_UART Error: Failed to Initialize IoTA Request...\r\n");
        return -1;
    }

    printf("\nIoT_UART: IoTA Request Initialized...\r\n");

    printf("\nIoT_UART: Starting Serialization of IoTA Request...\r\n");

    if ((ret = iota_serialize(&iota_inst_req, req, &req_ser, (uint32_t*)&req_ser_ln))
            != IOTA_OK) {
        printf("\nIoT_UART: Error: Failed to Serialize IoTA Request...\r\n");
        return -1;
    }

    printf("\nIoT_UART: IoTA Request Serialized...\r\n");

    //send request and and wait for measurement
    int rv;
    uint8_t *iota_meas;
    uint32_t iota_meas_len;

    if ((rv = uart_iota_meas(uart_filename, &iota_meas, (uint32_t*)&iota_meas_len, req_ser,
                             req_ser_ln)) != 0) {
        printf("\nIoT_UART: Error getting measurement from device over UART...\n");
        return -1;
    }

    iota_free(req_ser);

    iota_msg *resp;
    resp = malloc(sizeof(iota_msg));

    if ((ret = iota_init(&iota_inst_resp, meas_funcs, 0,
                         (uint8_t*)ns_pubcert_pem, ns_pubcert_pem_sz)) != IOTA_OK) {
        printf("\nIoTA Error: failed to initialize IoTA instance...\n");
        return -1;
    }

    printf("\nIoT_UART: IoTA Instance Initialized...\r\n");

    if ((ret = iota_req_init(&iota_inst_resp, &req, IOTA_SIGNED_FLAG | IOTA_ENCRYPTED_FLAG, IOTA_ACTION_MEAS, 0, NULL, 0,
                             nonce, sizeof(nonce), (uint8_t*)ns_pubcert_pem, ns_pubcert_pem_sz)) != IOTA_OK) {
        printf("\nIoT_UART Error: Failed to Initialize IoTA Response...\r\n");
        return -1;
    }

    printf("\nIoT_UART: IoTA Response Initialized...\r\n");

    printf("\nIoT_UART: Deserializing IoTA Response Received from IoT Device...\r\n");

    if ((ret = iota_deserialize(&iota_inst_resp, iota_meas, iota_meas_len, resp)) != IOTA_OK) {
        printf("\nIoT_UART: IoTA Deserialize Returned Error...\n");
        return -1;
    }

    /* process payload. Make it a measurement. */
    blob_data *blob = NULL;
    measurement_data *meas = NULL;

    meas = alloc_measurement_data(&blob_measurement_type);
    blob = container_of(meas, blob_data, d);

    unsigned char buffer[32] = {0};
    int i;

    for (i=0; i<=31; i++) {
        buffer[i] = resp->data[i];
    }

    blob->buffer = buffer;
    blob->size = 32;

    ret = measurement_node_add_rawdata(graph, node_id, &blob->d);
    if (ret != 0) {
        asp_logwarn("Error adding measurement data\n");
    }

    /* Cleanup */
    free_measurement_data(&blob->d);
    unmap_measurement_graph(graph);

    return 0;
}


