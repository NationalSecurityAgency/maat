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
#ifndef __PKG_DETAILS_TYPE_H__
#define __PKG_DETAILS_TYPE_H__

/*! \file
 * measurement_type for package details
 */

#include <measurement_spec/meas_spec-api.h>

#define PKG_DETAILS_TYPE_MAGIC	(3245)

#define PKG_DETAILS_TYPE_NAME	"pkg_details"

struct file_hash {
    size_t md5_len;
    char *md5;
    size_t filename_len;
    char *filename;
};

typedef struct pkg_details {
    struct measurement_data meas_data;
    size_t arch_len;
    char  *arch;
    size_t vendor_len;
    char  *vendor;
    size_t install_time_len;
    char  *install_time; //XXX: change type
    size_t url_len;
    char  *url;
    size_t source_len;
    char  *source; //XXX: or file type?
    size_t filehashs_len;
    GList *filehashs;
} pkg_details;

extern struct measurement_type pkg_details_measurement_type;

#endif /* __PKG_DETAILS_TYPE_H__ */

