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
#include <trousers/tss.h>
#include <trousers/trousers.h>

#ifndef __MAAT_UTIL_TPM_H__
#define __MAAT_UTIL_TPM_H__

/*! \file
 * struct and functions for controlling and using the TPM.
 */


#define MAAT_AIK_UUID {0, 0, 0, 0, 0, {0, 0, 0, 0, 0, 0xa}}

#ifndef TPM_SHA1_160_HASH_LEN
#define TPM_SHA1_160_HASH_LEN	(20)
#endif

#define TPM_QUOTE_FIXED		{'Q', 'U', 'O', 'T'}
#define TPM_VERSION_ARRAY	{1, 1, 0, 0}
#define TPM_PCR_VALUE_SIZE	0x14	/* PCR Value length */
#define TPM_PCR_VS_LOC		8	/* Byte location in flat struct */
#define TPM_PCR_SELECT_SIZE	3	/* PCR Select bitmask size */
#define TPM_PCR_SS_LOC		1	/* Byte location in flat struct */
#define TPM_PCR_SELECT		1	/* Flip the bit for PCR 16 */
#define TPM_PCR_16_LOC		4	/* PCR 16 location in flat struct */
#define TPM_PCR_SELECT_LENGTH	9	/* Length of hash prefix */

#define PCR_COMPOSITE_SIZE	(29)

struct tpm_state {
    int          lockfd;
    TSS_HCONTEXT ctx;
    TSS_HTPM	 tpm;
    TSS_HPCRS 	 pcrs;
    TSS_HKEY	 srk;
    TSS_HKEY	 aik;
    TSS_HPOLICY	 srk_policy;
    TSS_HPOLICY	 aik_policy;
};

void tpm_exit(struct tpm_state *tpm);
struct tpm_state *tpm_init(char *aik_password);
int tpm_read_pcr(struct tpm_state *tpm, uint32_t pcr, unsigned char **value,
                 uint32_t *size);
int tpm_reset_pcr(struct tpm_state *tpm, uint32_t pcr);
int tpm_extend_pcr(struct tpm_state *tpm, uint32_t pcr,
                   unsigned char *data, int size);
int tpm_quote_pcr(struct tpm_state *tpm, uint32_t pcr, char **signature,
                  uint32_t *size, TPM_NONCE nonce);

#endif /* __UTIL__TPM_H__ */
