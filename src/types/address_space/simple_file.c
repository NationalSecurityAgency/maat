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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include <glib.h>
#include <tpl.h>

#include <util/util.h>
#include <util/base64.h>
#include <simple_file.h>

static address *simple_file_alloc_address()
{
    struct simple_file_address *sfa;

    sfa = (struct simple_file_address *)
          malloc(sizeof(struct simple_file_address));
    if (!sfa)
        return NULL;
    sfa->filename	= NULL;
    sfa->a.space	= &simple_file_address_space;

    return (address *)sfa;
}

static void simple_file_free_address(address *a)
{
    struct simple_file_address *sfa = (struct simple_file_address *)a;
    if (sfa->filename)
        free(sfa->filename);
    free(sfa);
    return ;
}

static address *simple_file_coerce_address(const address *a)
{
    //	struct simple_file_address *sfa = (struct simple_file_address *)a;
    return NULL;
}

static address *simple_file_copy_address(const address *a)
{
    struct simple_file_address *orig = (struct simple_file_address *)a;
    struct simple_file_address *copy;

    copy = (struct simple_file_address *)simple_file_alloc_address();
    if (!copy)
        return (address *)NULL;

    copy->filename = strdup(orig->filename);

    return (address *)copy;
}

static char *simple_file_serialize_address(const address *a)
{
    const struct simple_file_address *sfa = (const struct simple_file_address *)a;
    /* tpl_node *tn; */
    /* void *tplbuf; */
    /* size_t tplsize; */
    /* //  int i; */
    /* char *b64; */

    /* tn = tpl_map("us", &sfa->a.space->magic, &sfa->filename); */
    /* tpl_pack(tn, 0); */

    /* tpl_dump(tn, TPL_MEM, &tplbuf, &tplsize); */

    /* dlog(3, "serialized address for %x of size %zd\n", */
    /*      sfa->a.space->magic, tplsize); */

    /* /\* Now, convert this to a string... base64 encode it *\/ */
    /* b64 = b64_encode(tplbuf, tplsize); */

    /* free(tplbuf); */
    /* tpl_free(tn); */
    /* return b64; */

    return b64_encode(sfa->filename, strlen(sfa->filename)+1);
}

static address *simple_file_parse_address(const char *a, size_t len)
{
    simple_file_address *sfa;
    size_t namelen;
    /* tpl_node *tn; */
    /* void *tplbuf; */
    /* size_t tplsize; */
    /* //        int i; */
    /* uint32_t as_magic; */

    /* tplbuf = b64_decode(a, &tplsize); */

    sfa = (simple_file_address*)alloc_address(&simple_file_address_space);
    if(!sfa)
        return NULL;

    sfa->filename = b64_decode(a, &namelen);
    if(sfa->filename == NULL || sfa->filename[namelen-1] != '\0') {
        g_free(sfa->filename);
        free(sfa);
        return NULL;
    }
    return &sfa->a;
}

static char *simple_file_addr_to_ascii(const address *a)
{
    const simple_file_address *fa = (const simple_file_address *)a;
    return strdup(fa->filename);
}

static address *simple_file_addr_from_ascii(const char *a)
{
    simple_file_address *fa = (simple_file_address *)malloc(sizeof(*fa));
    if(fa == NULL)
        return NULL;
    fa->filename = strdup(a);
    if(fa->filename == NULL) {
        free(fa);
        return NULL;
    }
    fa->a.space = &simple_file_address_space;

    return (address *)fa;

}

static gboolean simple_file_address_equal(const address *a, const address *b)
{
    struct simple_file_address *sfa = (struct simple_file_address *)a;
    struct simple_file_address *sfb = (struct simple_file_address *)b;

    if (!strcmp(sfa->filename, sfb->filename))
        return TRUE;
    return FALSE;
}

static guint simple_file_address_hash(const address *a)
{
    struct simple_file_address *sfa = (struct simple_file_address *)a;
    return strlen(sfa->filename);
}

static void *simple_file_read_bytes(address *a, size_t size)
{
    struct simple_file_address *sfa = (struct simple_file_address *)a;
    int fd;
    unsigned char *buf;
    int ret;

    fd = open(sfa->filename, O_RDONLY);
    if (fd < 0)
        return NULL;

    buf = (unsigned char *)malloc(size);
    if (!buf) {
        close(fd);
        return NULL;
    }

    ret = read(fd, buf, size);
    close(fd);
    if (ret < 0) {
        free(buf);
        return NULL;
    }

    return buf;
}

struct address_space simple_file_address_space = {
    .magic			= SIMPLE_FILE_MAGIC,
    .name                       = "simple_file",
    .alloc_address		= simple_file_alloc_address,
    .free_address		= simple_file_free_address,
    .coerce_address		= simple_file_coerce_address,
    .copy_address		= simple_file_copy_address,
    .serialize_address		= simple_file_serialize_address,
    .human_readable             = simple_file_addr_to_ascii,
    .from_human_readable        = simple_file_addr_from_ascii,
    .parse_address		= simple_file_parse_address,
    .address_equal		= simple_file_address_equal,
    .address_hash		= simple_file_address_hash,
    .read_bytes			= simple_file_read_bytes,
};
