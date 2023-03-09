/*
 * Copyright 2022 United States Government
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

/**
 * test-data.h: cpp macros defining paths to the data used by many tests.
 */

#define ASP_DIR       SRCDIR "/xml/asp-info"
#define SPEC_DIR      SRCDIR "/xml/specs"
#define APB_DIR       SRCDIR "/xml/apb-info"
#define SELECTOR_CFG  SRCDIR "/xml/am-selector/doc.xml"

#define ATTESTER_MEAS_SPEC_FILE   (SPEC_DIR "/dummy_attester_spec.xml")
#define APPRAISER_MEAS_SPEC_FILE (SPEC_DIR "/dummy_appraiser_spec.xml")

#define ASP_NAME ("dummy")

#define APB_UUID                 ("7d70e1c4-b4e2-4935-be6d-c8692a941793")
#define ATTESTER_MEAS_SPEC_UUID  ("15c7ba17-ef11-4676-8f8e-5cdeb23d13a2")
#define APPRAISER_MEAS_SPEC_UUID ("579eef42-635a-42c4-a6a3-e333927944fe")
#define ASP_UUID                 ("96c7e765-b4b3-4808-b0d9-bff7b408dc2a")
#define ATTESTER_PHRASE "(USM attest)"
#define APPRAISER_PHRASE "(USM appraise)"

#define CREDS_DIR       SRCDIR "/creds"
#define CA_CERT         (CREDS_DIR "/ca.pem")
#define ATTESTER_KEY    (CREDS_DIR "/client.key")
#define ATTESTER_CERT   (CREDS_DIR "/client.pem")
#define APPRAISER_KEY   (CREDS_DIR "/server.key")
#define APPRAISER_CERT  (CREDS_DIR "/server.pem")
#define TPMPASS         "maatpass"
#define AKCTX           (CREDS_DIR "/ak.ctx")
#define AKPUB           (CREDS_DIR "/akpub.pem")

#define LIBMAAT_APBMAIN  (BUILDDIR "/../am/apbmain")
#define LIBMAAT_ASPMAIN  (BUILDDIR "/../asp/aspmain")

#define GRAPH_TEST_FILE_0 SRCDIR "/xml/test-files/serialization_test.xml"
#define GRAPH_TEST_FILE_1 SRCDIR "/xml/test-files/merge_test_1.xml"
#define GRAPH_TEST_FILE_2 SRCDIR "/xml/test-files/merge_test_2.xml"

#define CSV_FILE SRCDIR "/test_data.csv"
#define CSV_WRITE_FILE SRCDIR "/test_data_write.csv"

#include <util/util.h>

static inline void setup(void)
{
    setenv("LIBMAAT_APBMAIN", LIBMAAT_APBMAIN, 1);
    setenv("LIBMAAT_ASPMAIN", LIBMAAT_ASPMAIN, 1);
    libmaat_init(0, 5);
}
