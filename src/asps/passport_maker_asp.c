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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <inttypes.h>
#include <fcntl.h>

#include <util/util.h>
#include <util/maat-io.h>
#include <util/sign.h>
#include <util/base64.h>

#include <asp/asp-api.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>

#include <maat-basetypes.h>
#include <sys/types.h>
#include <client/maat-client.h>

#define ASP_NAME "passport_maker_asp"

#define TIMEOUT 100
#define MAX_TM_SZ 21

int out_fd = 0, in_fd = 0;

/*! \file passport_maker_asp.c
 *
 * This ASP uses the passed-in values to create a passport
 * and sends it on to result chan
 */


int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    asp_logdebug("Initialized passport_maker_ASP\n");
    return 0;
}


int asp_exit(int status)
{
    asp_logdebug("Exiting passport_maker_ASP\n");
    return status;
}


static int send(unsigned char *buf, size_t buf_size)
{
    gsize bytes_written = 0;
    int status = maat_write_sz_buf(out_fd, buf, buf_size, &bytes_written, TIMEOUT);
    if (status != 0) {
        asp_logerror("failed to pipe passport back to appraiser\n");
        return -EIO;
    }
    if (bytes_written != (buf_size + sizeof(uint32_t))) {
        asp_logerror("wrote %zu (expected to write %ld)\n", bytes_written, buf_size);
        return -EIO;
    }

    return status;
}


int asp_measure(int argc, char *argv[])
{
    asp_logdebug("in passport_maker_ASP MEASURE()\n");

    int ret = 0;

    char *target_type = NULL;
    char *target = NULL;
    char *resource = NULL;
    char *result = NULL;
    const char *keyfile;
    const char *keypass;
    char *copland_phrase = NULL;

    time_t currtime;
    struct tm *tm;
    char startdate[MAX_TM_SZ];
    const char *period = "300"; /*passport period is set to 300seconds*/

    unsigned char *passport_buf = NULL;
    unsigned char *tmp = NULL;
    size_t passport_sz = 0;
    unsigned int size;
    unsigned char *signature_buf = NULL;
    size_t signature_len = 0;
    char *b64sig;
    char *encoded_passport;

    //check arguments
    if( (argc < 8) ||
            ((target_type = argv[3]) == NULL) ||
            ((target = argv[4]) == NULL) ||
            ((resource = argv[5]) == NULL) ||
            ((result = argv[6]) == NULL) ||
            (!(keyfile = argv[7])) ) {
        asp_logerror("Usage: "ASP_NAME"<target_type> <target> <resource> <evaluation> <keyfile> [<keypass]\n");
        return -1;
    } else if (argc == 9) {
        keypass = argv[8];
    } else {
        keypass = NULL;
    }

    in_fd = atoi(argv[1]);
    out_fd = atoi(argv[2]);

    //get time
    time(&currtime);
    tm = gmtime(&currtime);
    memset(startdate, '0', MAX_TM_SZ);
    strftime(startdate, MAX_TM_SZ, "%Y-%m-%dT%H:%M:%SZ", tm);

    //get copland phrase based on resource
    if (strcmp(resource, "full") == 0) {
        copland_phrase = "((USM full) -> SIG)";
    } else if (strcmp(resource, "processes") == 0) {
        copland_phrase = "((USM processes) -> SIG)";
    } else if (strcmp(resource, "packages") == 0) {
        copland_phrase = "((USM pkginv) -> SIG)";
    } else if (strcmp(resource, "hashfiles") == 0) {
        copland_phrase = "((USM hashfiles) -> SIG)";
    } else if (strcmp(resource, "mtab") == 0) {
        copland_phrase = "((USM mtab) -> SIG)";
    } else if (strcmp(resource, "got_measure") == 0) {
        copland_phrase = "((USM got) -> SIG)";
    } else if (strcmp(resource, "hashfile") == 0) {
        copland_phrase = "((USM hashfile file) -> SIG):file=/bin/ls";
    } else {
        asp_logerror("resource %s not recognized\n", resource);
        return -1;
    }

    //get passport as string
    passport_sz = strlen(target_type) + strlen(target) + strlen(resource) +
                  strlen(copland_phrase) + strlen(result) + strlen(startdate) +
                  strlen(period) + 10; /*account for formatting*/
    passport_buf = malloc(passport_sz);
    if (passport_buf == NULL) {
        asp_logerror("failed to allocate memory for passport\n");
        return -1;
    }

    // Cast is justified because the function does not regard the signedness of the input
    snprintf((char *)passport_buf, passport_sz, "%s,%s,%s,%s,%s,%s,%s",
             target_type, target, resource, copland_phrase, result, startdate, period);
    passport_buf[passport_sz-1] = 0;

    //sign buf
    // Cast is justified because the function does not regard the signedness of the input
    passport_sz = strlen((char *)passport_buf);
    size = (unsigned int)passport_sz;

    signature_buf = sign_buffer_openssl(passport_buf, size, keyfile, keypass, &signature_len);
    if (!signature_buf) {
        asp_logerror("Error: could not generate signature\n");
        free(passport_buf);
        return -1;
    }

    b64sig = b64_encode(signature_buf, signature_len);
    if (!b64sig) {
        asp_logerror("Error: could not base64 encode signature\n");
        free(passport_buf);
        free(signature_buf);
        return -1;
    }
    free(signature_buf);

    //add signature to passport
    passport_sz += strlen(b64sig) + 2; /*account for formatting*/
    tmp = realloc(passport_buf, passport_sz * sizeof(unsigned char));
    if(tmp == NULL) {
        asp_logerror("Error: realloc of passport buf failed\n");
        free(passport_buf);
        return -1;
    }
    passport_buf = tmp;

    //Casts are justified because the function does not regard the signedness of the input
    strcat((char *)passport_buf, ",");
    strcat((char *)passport_buf, (char*)b64sig);
    passport_buf[passport_sz-1] = 0;
    b64_free(b64sig);

    //encode passport
    encoded_passport = b64_encode(passport_buf, passport_sz);
    if (!encoded_passport) {
        asp_logerror("Error: could not base64 encode passport\n");
        free(passport_buf);
        return -1;
    }
    free(passport_buf);

    //send
    ret = send((unsigned char*)encoded_passport, strlen(encoded_passport)+1);
    free(encoded_passport);

    return ret;
}
