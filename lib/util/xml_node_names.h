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
#ifndef __MAAT_XML_NODE_NAMES_H__
#define __MAAT_XML_NODE_NAMES_H__


/**
 * @brief Define macros for the names of the various XML nodes, as well as the
 * property names and values.  This is to ensure that we don't use string
 * literals in the code, which can be brittle.
 */
#define XML_NODENAME_ATTESTATION_CREDENTIAL "AttestationCredential"
#define XML_NODENAME_BIT                    "bit"
#define XML_NODENAME_CANONICALIZATION       "canonicalizationmethod"
#define XML_NODENAME_CONTRACT               "contract"
#define XML_NODENAME_DIGEST_METHOD          "digestmethod"
#define XML_NODENAME_KEYINFO                "keyinfo"
#define XML_NODENAME_NONCE                  "nonce"
#define XML_NODENAME_OBJECT                 "object"
#define XML_NODENAME_REFERENCE              "reference"
#define XML_NODENAME_SIGNATURE              "signature"
#define XML_NODENAME_SIGNATURE_METHOD       "signaturemethod"
#define XML_NODENAME_SIGNATURE_VALUE        "signaturevalue"
#define XML_NODENAME_SIGINFO                "signedinfo"

#define XML_PROPNAME_ALGORITHM              "algorithm"
#define XML_PROPNAME_ID                     "id"
#define XML_PROPNAME_TYPE                   "type"
#define XML_PROPNAME_URI                    "URI"

#define XML_PROPVAL_XML_C14N_1_0            "XML C14N 1.0"
#define XML_PROPVAL_RSA                     "RSA"
#define XML_PROPVAL_RSASSA                  "RSASSA"
#define XML_PROPVAL_SHA_1                   "SHA-1"  // DEPRECATED!
#define XML_PROPVAL_SHA_256                 "SHA-256"

#define XML_PROPVAL_TPMS_ATTEST             "tpms_attest"
#define XML_PROPVAL_HASH_TPMS_ATTEST        ("#" XML_PROPVAL_TPMS_ATTEST)

#define XML_XPATH_CONTRACT_NONCE            "/" XML_NODENAME_CONTRACT "/" XML_NODENAME_NONCE

#endif /* __MAAT_XML_NODE_NAMES_H__ */
