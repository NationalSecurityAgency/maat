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

#include <config.h>

#include <errno.h>
#include <string.h>

#include <exe_sec_ctxt.h>
#include <util/xml_util.h>
#include <asp_info.h>

void free_asp(struct asp *asp)
{
    if(asp == NULL) {
        return;
    }

    if (asp->filename) {
        free(asp->filename);
    }
    if (asp->name) {
        free(asp->name);
    }
    if (asp->desc) {
        free(asp->desc);
    }

    free_xml_file_info(asp->file);

    free_exe_sec_ctxt(&asp->desired_sec_ctxt);

    free(asp);
}

/**
 * Allocates memory and copies the contents of the src asp struct to
 * the dest struct.
 * It is the responsibility of the calling party to free dest with free_asp()
 */
int copy_asp(struct asp **dest, struct asp *src)
{
    int ret_val = 0;
    struct asp *tmp;
    *dest = NULL;

    if(src == NULL) {
        return -EINVAL;
    }

    tmp = malloc(sizeof(struct asp));
    if(tmp == NULL) {
        goto nomem_error;
    }

    tmp->metadata_version = src->metadata_version;

    //Strings
    tmp->filename = NULL;
    if (src->filename) {
        tmp->filename = strdup(src->filename);
        if (tmp->filename == NULL) {
            goto filename_error;
        }
    }

    tmp->name = NULL;
    if (src->name) {
        tmp->name = strdup(src->name);
        if(tmp->name == NULL) {
            goto name_error;
        }
    }

    tmp->desc = NULL;
    if (src->desc) {
        tmp->desc = strdup(src->desc);
        if(tmp->desc == NULL) {
            goto desc_error;
        }
    }

    //Special
    uuid_copy(tmp->uuid, src->uuid);
    tmp->pid = 0;

    if((ret_val = copy_xml_file_info(&tmp->file, src->file)) != 0) {
        goto file_error;
    }

    if((ret_val = copy_exe_sec_ctxt(&tmp->desired_sec_ctxt, &src->desired_sec_ctxt)) != 0) {
        goto exe_sec_ctxt_error;
    }

    *dest = tmp;

    return 0;

exe_sec_ctxt_error:
    free_xml_file_info(tmp->file);
file_error:
    free(tmp->desc);
desc_error:
    free(tmp->name);
name_error:
    free(tmp->filename);
filename_error:
    free(tmp);
nomem_error:
    return -ENOMEM;
}
