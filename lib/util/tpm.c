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

/**
 * tpm.c: wrappers around TSS routines for interacting with the TPM.
 */
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include <glib.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <trousers/tss.h>
#include <trousers/trousers.h>

#include <util/checksum.h>
#include <util/tpm.h>

#define TPM_LOCK "/tmp/.maat_tpm_lock"

#define TSS_TEST(ret)	do {				\
	if (ret != TSS_SUCCESS) {			\
		fprintf(stderr, "[%s:%d]\tTPM operation failed: %s (%d)\n", \
			__FUNCTION__, __LINE__, Trspi_Error_String(ret), \
			ret);						\
		goto out;				\
	}						\
} while(0)

void tpm_exit(struct tpm_state *tpm)
{
    if (tpm->pcrs)
        Tspi_Context_CloseObject(tpm->ctx, tpm->pcrs);

    if (tpm->aik_policy)
        Tspi_Policy_FlushSecret(tpm->aik_policy);

    if (tpm->srk_policy)
        Tspi_Policy_FlushSecret(tpm->srk_policy);

    if (tpm->aik)
        Tspi_Key_UnloadKey(tpm->aik);

    if (tpm->ctx) {
        Tspi_Context_FreeMemory(tpm->ctx, NULL);
        Tspi_Context_Close(tpm->ctx);
    }
    close(tpm->lockfd);

    free(tpm);
}

struct tpm_state *tpm_init(char *aik_password)
{
    struct tpm_state *tpm;
    TSS_RESULT ret;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    TSS_UUID AIK_UUID = MAAT_AIK_UUID;
    unsigned char srk_secret[] = TSS_WELL_KNOWN_SECRET;
    struct flock lock;

    tpm = (struct tpm_state *)malloc(sizeof(struct tpm_state));
    if (!tpm) {
        perror("Error allocating TPM state struct");
        return NULL;
    }
    memset(tpm, 0, sizeof(struct tpm_state));

    if((tpm->lockfd = open(TPM_LOCK, O_CREAT|O_WRONLY, S_IWUSR)) < 0) {
        fprintf(stderr, "Failed to open tpm lockfile! %s : %s\n",
                TPM_LOCK, strerror(errno));
        goto out;
    }
lock_again:
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    if(fcntl(tpm->lockfd, F_SETLKW, &lock) != 0) {
        if(errno == EINTR) {
            goto lock_again;
        }
        fprintf(stderr, "Failed to lock lockfile! : %s\n", strerror(errno));
        goto out;
    }

    /* Create a context and connect to the TPM */
    ret = Tspi_Context_Create(&tpm->ctx);
    TSS_TEST(ret);

    ret = Tspi_Context_Connect(tpm->ctx, NULL);
    TSS_TEST(ret);

    ret = Tspi_Context_GetTpmObject(tpm->ctx, &tpm->tpm);
    TSS_TEST(ret);

    /* load the SRK */
    ret = Tspi_Context_LoadKeyByUUID(tpm->ctx, TSS_PS_TYPE_SYSTEM,
                                     SRK_UUID, &tpm->srk);
    TSS_TEST(ret);

    /* Set SRK secret XXX rethink location of this call */
    ret = Tspi_GetPolicyObject(tpm->srk,
                               TSS_POLICY_USAGE, &tpm->srk_policy);
    TSS_TEST(ret);

    ret = Tspi_Policy_SetSecret(tpm->srk_policy, TSS_SECRET_MODE_SHA1,
                                sizeof(srk_secret), srk_secret);
    TSS_TEST(ret);

    /* Load AIK */
    ret = Tspi_Context_GetKeyByUUID(tpm->ctx, TSS_PS_TYPE_SYSTEM,
                                    AIK_UUID, &tpm->aik);
    TSS_TEST(ret);

    ret = Tspi_Key_LoadKey(tpm->aik, tpm->srk);
    TSS_TEST(ret);

    ret = Tspi_GetPolicyObject(tpm->aik,
                               TSS_POLICY_USAGE, &tpm->aik_policy);
    TSS_TEST(ret);

    ret = Tspi_Policy_SetSecret(tpm->aik_policy, TSS_SECRET_MODE_PLAIN,
                                strlen(aik_password), aik_password);
    TSS_TEST(ret);

    /* Grab a handle to the PCRs */
    ret = Tspi_Context_CreateObject(tpm->ctx, TSS_OBJECT_TYPE_PCRS, 0,
                                    &tpm->pcrs);
    TSS_TEST(ret);

    return tpm;
out:
    tpm_exit(tpm);
    return NULL;
}

int tpm_read_pcr(struct tpm_state *tpm, uint32_t pcr, unsigned char **value,
                 uint32_t *size)
{
    TSS_RESULT ret;

    ret = Tspi_TPM_PcrRead(tpm->tpm, pcr, size, value);
    TSS_TEST(ret);
    return 0;
out:
    return -1;
}

int tpm_reset_pcr(struct tpm_state *tpm, uint32_t pcr)
{
    TSS_RESULT ret;

    ret = Tspi_PcrComposite_SelectPcrIndex(tpm->pcrs, pcr);
    TSS_TEST(ret);

    ret = Tspi_TPM_PcrReset(tpm->tpm, tpm->pcrs);
    TSS_TEST(ret);

    return 0;
out:
    return -1;
}

int tpm_extend_pcr(struct tpm_state *tpm, uint32_t pcr,
                   unsigned char *data, int size)
{
    TSS_RESULT ret;
    UINT32 ulNewPcrValueLength;
    BYTE* NewPcrValue;

    ret = Tspi_PcrComposite_SelectPcrIndex(tpm->pcrs, pcr);
    TSS_TEST(ret);

    /* The last two parameters cannot be null or command fails. */
    ret = Tspi_TPM_PcrExtend(tpm->tpm, pcr, size, data, NULL,
                             &ulNewPcrValueLength, &NewPcrValue);
    TSS_TEST(ret);

    return 0;
out:
    return -1;
}

int tpm_quote_pcr(struct tpm_state *tpm, uint32_t pcr, char **signature,
                  uint32_t *size, TPM_NONCE nonce)
{
    TSS_RESULT ret;
    TSS_VALIDATION validation;

    memset(&validation, 0, sizeof(validation));
    validation.ulExternalDataLength = sizeof(nonce.nonce);
    validation.rgbExternalData = nonce.nonce;
    validation.rgbData = NULL;
    validation.rgbValidationData = NULL;
    validation.ulValidationDataLength = 0;

    ret = Tspi_PcrComposite_SelectPcrIndex(tpm->pcrs, pcr);
    TSS_TEST(ret);

    ret = Tspi_TPM_Quote(tpm->tpm, tpm->aik, tpm->pcrs, &validation);
    TSS_TEST(ret);

    memcpy(size, &validation.ulValidationDataLength, sizeof(uint32_t));
    *signature = (unsigned char *)malloc(*size);
    memcpy(*signature, validation.rgbValidationData, *size);

    return 0;

out:
    return -1;
}
