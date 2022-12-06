
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

#ifndef __REPORT_MEASUREMENT_TYPE_H__
#define __REPORT_MEASUREMENT_TYPE_H__

#include <measurement_spec/meas_spec-api.h>
#include <libxml/tree.h>

#define REPORT_MEASUREMENT_TYPE_MAGIC (0x10000000)
#define REPORT_MEASUREMENT_TYPE_NAME "report"

/**
 * Some rough guidelines about segregating levels of report
 * messages.  Allows UI to filter on desired results.
 *
 * Note: due to serialization technique, there can only be 10
 * levels here (0-9).
 */
enum report_levels {
    REPORT_ERROR = 0,
    REPORT_WARNING,
    REPORT_INFO,
    REPORT_DEBUG
};

/**
 * Represents textual data that should be included in the attestation
 * response contract.  In the future this may expand to support
 * arbitrary structured data for reporting.  Supports attribute
 * "text_data"
 */
typedef struct report_data {
    measurement_data d;
    enum report_levels loglevel;
    char *text_data;
    size_t text_data_len;
} report_data;

/**
 * Create a report data object with the given text block. The newly
 * created data object takes ownership of the buffer pointed to be
 * @text. Log level defaults to REPORT_INFO if unspecified.
 */
report_data *report_data_with_text(char *text, size_t length);
report_data *report_data_with_level_and_text(enum report_levels level,
        char *text, size_t length);

/**
 * Set the text data of an existing report data measurement.  The
 * measurement frees its current text data and takes ownership of the
 * buffer pointed to be @text. Log level defaults to REPORT_INFO.
 */
void report_data_set_text(report_data *rmd, char *text, size_t length);


/**
 * Serialize the data as an xmlNode suitable for adding to a
 * <data ...> entry in an attestation response contract.
 */
xmlNode *report_data_to_xml(report_data *rmd);

extern measurement_type report_measurement_type;

#endif
