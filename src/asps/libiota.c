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

/*! \file
 * libiota
*/

#include <stdlib.h>
#include <string.h>

#include <../asps/libiota.h>

static iota_ret iota_msg_init(iota *iota_inst, iota_msg **msg,
                              void *data, uint32_t data_len,
                              uint8_t type, uint32_t flags,
                              iota_action action, uint16_t id,
                              uint8_t meas_type, uint8_t ret_code,
                              uint8_t *nonce, uint32_t nonce_len,
                              uint8_t *dest_cert, uint32_t dest_cert_len)
{
    iota_ret ret = IOTA_OK;

    if (!((*msg) = iota_malloc(sizeof(iota_msg)))) {
        return IOTA_ERR_MALLOC_FAIL;
    }

    (*msg)->data = NULL;
    (*msg)->data_len = 0;
    if (data_len > 0) {
        if (!((*msg)->data = iota_malloc(data_len))) {
            iota_free(*msg);
            return IOTA_ERR_MALLOC_FAIL;
        }
    }
    iota_memcpy((*msg)->data, data, data_len);
    (*msg)->data_len = data_len;

    (*msg)->nonce = NULL;
    (*msg)->nonce_len = 0;
    if (nonce_len > 0) {
        if (!((*msg)->nonce = iota_malloc(nonce_len))) {
            iota_free((*msg)->data);
            iota_free(*msg);
            return IOTA_ERR_MALLOC_FAIL;
        }
        iota_memcpy((*msg)->nonce, nonce, nonce_len);
        (*msg)->nonce_len = nonce_len;
    }

    (*msg)->cert = NULL;
    (*msg)->cert_len = 0;
    if (iota_inst->cert != NULL) {
        if (!((*msg)->cert = iota_malloc(iota_inst->cert_len))) {
            iota_free((*msg)->nonce);
            iota_free((*msg)->data);
            iota_free(*msg);
            return IOTA_ERR_MALLOC_FAIL;
        }
        iota_memcpy((*msg)->cert, iota_inst->cert, iota_inst->cert_len);
        (*msg)->cert_len = iota_inst->cert_len;
    }

    (*msg)->dest_cert  = NULL;
    (*msg)->dest_cert_len = 0;
    (*msg)->dest_cert2 = NULL;
    (*msg)->dest_cert2_len = 0;
    if (dest_cert_len != 0) {
        if ((!((*msg)->dest_cert =  iota_malloc(dest_cert_len)))
                ||
                (!((*msg)->dest_cert2 = iota_malloc(dest_cert_len)))) {
            iota_free((*msg)->cert);
            iota_free((*msg)->nonce);
            iota_free((*msg)->data);
            if ((*msg)->dest_cert != NULL)
                iota_free((*msg)->dest_cert);
            iota_free(*msg);
            return IOTA_ERR_MALLOC_FAIL;
        }
        iota_memcpy((*msg)->dest_cert,  dest_cert, dest_cert_len);
        iota_memcpy((*msg)->dest_cert2, dest_cert, dest_cert_len);
        (*msg)->dest_cert_len = dest_cert_len;
        (*msg)->dest_cert2_len = dest_cert_len;
    }

    (*msg)->hdr.version = IOTA_VERSION;
    (*msg)->hdr.len = 0;
    (*msg)->flags = flags;
    (*msg)->sig_len = 0;
    (*msg)->sig = NULL;
    (*msg)->type = type;
    (*msg)->action = action;
    (*msg)->id = id;
    (*msg)->meas_type = meas_type;
    (*msg)->ret = ret_code;

    (*msg)->sig_len = 0;
    (*msg)->sig = NULL;

    return ret;
}

iota_ret iota_req_init(iota *iota_inst, iota_msg **msg, uint32_t flags,
                       iota_action action, uint16_t id, uint8_t *arg,
                       uint32_t arg_len, uint8_t *nonce, uint32_t nonce_len,
                       uint8_t *dest_cert, uint32_t dest_cert_len)
{
    return iota_msg_init(iota_inst, msg, arg, arg_len, IOTA_REQUEST, flags, action, id, 0,
                         0, nonce, nonce_len, dest_cert, dest_cert_len);
}

void iota_msg_deinit(iota_msg **msg)
{
    if ((*msg)->cert != NULL)
        iota_free((*msg)->cert);
    if ((*msg)->dest_cert != NULL)
        iota_free((*msg)->dest_cert);
    if ((*msg)->nonce != NULL)
        iota_free((*msg)->nonce);
    if ((*msg)->dest_cert2 != NULL)
        iota_free((*msg)->dest_cert2);
    if ((*msg)->data != NULL)
        iota_free((*msg)->data);
    if ((*msg)->sig != NULL)
        iota_free((*msg)->sig);
    iota_free(*msg);
    *msg = NULL;
}

static iota_ret iota_resp_init(iota *iota_inst, iota_msg **msg,
                               void *data, uint32_t data_len,
                               uint32_t flags, iota_action action, uint16_t id,
                               uint8_t meas_type, uint8_t ret, const iota_msg *req)
{
    iota_ret rv = IOTA_OK;
    rv = iota_msg_init(iota_inst, msg, data, data_len, IOTA_RESPONSE,
                       flags, action, id, meas_type, ret,
                       req->nonce, req->nonce_len,
                       req->cert, req->cert_len);
    return rv;
}

static iota_ret _iota_list(iota *iota_inst, const iota_msg *req, iota_msg **resp)
{
    iota_ret ret;
    iota_meas_func func;
    size_t i;
    iota_list_entry *entries = NULL;
    iota_list_entry *entry = NULL;
    size_t entries_len = sizeof(iota_list_entry) * iota_inst->num_funcs;

    if (!(entries = iota_malloc(entries_len))) {
        return IOTA_ERR_MALLOC_FAIL;
    }

    entry = entries;

    for (i = 0; i < iota_inst->num_funcs; i++) {
        func = iota_inst->meas_funcs[i];
        entry->id = (uint16_t)i;
        iota_memcpy(entry->name, func.name, IOTA_MEAS_FUNC_NAME_LEN);
        entry->type = func.type;
        entry++;
    }

    if ((ret = iota_resp_init(iota_inst, resp,
                              (uint8_t*)entries, (uint32_t)entries_len,
                              iota_inst->flags, IOTA_ACTION_LIST, req->id,
                              req->meas_type, IOTA_OK, req)) != IOTA_OK) {
        iota_free(entries);
        return ret;
    }

    iota_free(entries);

    return IOTA_OK;
}

static iota_ret _iota_measure(iota *iota_inst, const iota_msg *req, iota_msg **resp)
{
    iota_meas_func meas_func;
    iota_ret ret;
    iota_ret meas_ret;
    uint8_t *meas = NULL;
    uint32_t measlen;

    if (req->id >= iota_inst->num_funcs) {
        if ((ret = iota_resp_init(iota_inst, resp, NULL, 0, iota_inst->flags,
                                  IOTA_ACTION_MEAS, req->id, req->meas_type,
                                  IOTA_ERR_BAD_ID, req)) != IOTA_OK) {
            return ret;
        }

        return IOTA_OK;
    }

    meas_func = iota_inst->meas_funcs[req->id];

    if ((meas_ret = meas_func.func(req->data, req->data_len, &meas, &measlen))
            != IOTA_OK) {
        if ((ret = iota_resp_init(iota_inst, resp, NULL, 0, iota_inst->flags,
                                  IOTA_ACTION_MEAS, req->id, req->meas_type,
                                  meas_ret, req)) != IOTA_OK) {
            return ret;
        }

        return IOTA_OK;
    }

    if ((ret = iota_resp_init(iota_inst, resp, meas, measlen, iota_inst->flags,
                              IOTA_ACTION_MEAS, req->id,
                              meas_func.type,
                              IOTA_OK, req)) != IOTA_OK) {
        return ret;
    }

    // NULL measurements are allowed
    if (meas) {
        if (meas_func.free_func) {
            meas_func.free_func(meas);
        } else {
            iota_free(meas);
        }
    }

    return IOTA_OK;
}

iota_ret iota_init(iota *iota_inst, const iota_meas_func *funcs, uint32_t flags,
                   uint8_t *cert, uint32_t cert_len)
{
    uint16_t num_funcs = 0;

    if (!iota_inst) {
        return IOTA_ERR_BAD_INIT;
    }

    iota_inst->meas_funcs = funcs;

    while (funcs && funcs->func) {
        num_funcs++;
        funcs++;
    }

    iota_inst->num_funcs = num_funcs;
    iota_inst->flags = flags;

    iota_inst->cert_len = 0;
    iota_inst->cert = iota_malloc(cert_len);
    if (iota_inst->cert == NULL)
        return IOTA_ERR_MALLOC_FAIL;
    iota_memcpy(iota_inst->cert, cert, cert_len);
    iota_inst->cert_len = cert_len;

    return IOTA_OK;
}

iota_ret iota_do(iota *iota_inst, const iota_msg *req, iota_msg **resp)
{
    iota_ret ret;

    if (iota_inst->flags != req->flags) {
        return IOTA_ERR_BAD_REQ;
    }

    switch (req->action) {
    case IOTA_ACTION_MEAS:
        ret = _iota_measure(iota_inst, req, resp);
        break;
    case IOTA_ACTION_LIST:
        ret = _iota_list(iota_inst, req, resp);
        break;
    default:
        ret = IOTA_ERR_BAD_REQ;
    }

    return ret;
}

// on some ARM architectures, we must write on word boundaries (4 bytes).
#define SER4(x) *p = (uint32_t)x; p++;
#define ROUNDUP(x) (((x+3)/4)*4)
#define SERN(buf,len) SER4(len); iota_memcpy(p, buf, len); p += ROUNDUP(len)/4;

// we don't use iota_inst in this function, but for consistency of interface, request it anyway.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
iota_ret iota_serialize(iota *iota_inst, iota_msg* msg,
                        uint8_t** outbuf, uint32_t *outbuf_len)
{
    iota_inst;
    msg->hdr.len = 14*4 +
                   ROUNDUP(msg->cert_len) + ROUNDUP(msg->nonce_len) +
                   ROUNDUP(msg->dest_cert_len) + ROUNDUP(msg->dest_cert2_len) + ROUNDUP(msg->data_len);
    *outbuf = malloc(msg->hdr.len);
    if (*outbuf == NULL) return IOTA_ERR_MALLOC_FAIL;
    memset(*outbuf, 0, msg->hdr.len);
    uint32_t* p = (uint32_t*)*outbuf;

    SER4(msg->hdr.version);
    SER4(msg->hdr.len);
    SER4(msg->flags);

    SERN(msg->dest_cert, msg->dest_cert_len);

    SERN(msg->cert, msg->cert_len);

    // the above stays unencrypted, the rest is encrypted (if encryption enabled)
    uint32_t unencrypted_len = (uint8_t*)p - *outbuf;
    SER4(msg->type);
    SER4(msg->action);
    SER4(msg->id);
    SER4(msg->meas_type);
    SER4(msg->ret);

    SERN(msg->nonce, msg->nonce_len);

    SERN(msg->dest_cert2, msg->dest_cert2_len);

    SERN(msg->data, msg->data_len);
    uint32_t* ser_msg_end = p;

    if (msg->flags & IOTA_SIGNED_FLAG) {
        iota_ret ret;
        uint8_t *sig = NULL;
        uint32_t sig_len = 0;
        // don't sign the header; the length field is too unstable
        uint8_t *sign_region_start = *outbuf + sizeof(uint32_t)*2;
        if (((ret = iota_sign(sign_region_start,
                              (uint32_t)((uint8_t*)ser_msg_end - sign_region_start),
                              &sig, &sig_len)) != IOTA_OK)
                || (sig == NULL)) {
            iota_free(*outbuf);
            *outbuf_len = 0;
            return ret;
        }
        // if not already on a 4-byte boundary, pad out to one.
        // this should never actually happen in practice.
        unsigned int pad;
        for (pad = 0; pad < sig_len % 4; pad++) {
            *p = 0;
            p++;
        }
        *(uint32_t*)p = sig_len;
        p ++;
        // we need to allocate more space for the signature.
        uint8_t* new_outbuf = malloc(msg->hdr.len + sig_len);
        if (new_outbuf == NULL) {
            *outbuf_len = 0;
            iota_free(*outbuf);
            return IOTA_ERR_MALLOC_FAIL;
        }
        iota_memcpy(new_outbuf, *outbuf, msg->hdr.len);
        iota_free(*outbuf);
        *outbuf = new_outbuf;
        p = (uint32_t*)(*outbuf + msg->hdr.len);
        msg->hdr.len += sig_len;
        // update length field in serialized buffer
        ((uint32_t*)*outbuf)[1] = msg->hdr.len;
        iota_memcpy(p, sig, sig_len);
        p += ROUNDUP(sig_len)/4;
        iota_free(sig);
    } else {
        *(uint32_t*)p = 0;
        p ++;
    }
    if (msg->flags & IOTA_ENCRYPTED_FLAG) {
        uint8_t* enc;
        uint32_t enc_len;
        iota_ret rv;
        // length of section to be encrypted, before padding
        uint32_t cleartext_len = (uint8_t*)p - *outbuf - unencrypted_len;
        if ((rv = iota_encrypt(*outbuf + unencrypted_len, cleartext_len,
                               msg->dest_cert, msg->dest_cert_len,
                               &enc, &enc_len)) != 0) {
            iota_free(*outbuf);
            return rv;
        }
        if (unencrypted_len + enc_len > msg->hdr.len) {
            uint8_t* new_outbuf = NULL;
            new_outbuf = iota_malloc((size_t)(unencrypted_len + enc_len));
            if (new_outbuf == NULL) {
                *outbuf_len = 0;
                iota_free(*outbuf);
                return IOTA_ERR_MALLOC_FAIL;
            }
            iota_memcpy(new_outbuf, *outbuf, unencrypted_len);
            iota_free(*outbuf);
            *outbuf = new_outbuf;
        }
        msg->hdr.len = (uint32_t)(unencrypted_len + enc_len);
        (*(uint32_t**)outbuf)[1] = msg->hdr.len; // update already-serialized buffer
        iota_memcpy(*outbuf + unencrypted_len, enc, enc_len);
        iota_free(enc);
    }
    *outbuf_len = msg->hdr.len;
    return IOTA_OK;
}
#pragma GCC diagnostic pop // Stop ignoring -Wunused-parameter

#define DES4(x) x = *p; p++;
#define DES4_T(x,type) x = (type)*p; p++;
#define DESN(buf, len) len = *p; p++; buf = iota_malloc(len);    \
    if (buf) { iota_memcpy(buf, p, len); p += ROUNDUP(len)/4; }

iota_ret iota_deserialize(iota *iota_inst,
                          uint8_t* msg_bytes, uint32_t msg_bytes_sz,
                          iota_msg *out)
{
    iota_ret ret;
    iota_msg tmp;
    if (msg_bytes_sz < sizeof(iota_msg_hdr))
        return IOTA_ERR_MALFORMAT;
    uint8_t* msg_bytes_cp = malloc(msg_bytes_sz);
    if (msg_bytes_cp == NULL) return IOTA_ERR_MALLOC_FAIL;
    memcpy(msg_bytes_cp, msg_bytes, msg_bytes_sz);

    uint32_t *p = (uint32_t*)msg_bytes_cp;
    uint32_t version;
    uint32_t len;

    DES4(version);
    DES4(len);
    if (len < msg_bytes_sz) {
        iota_free(msg_bytes_cp);
        return IOTA_ERR_MALFORMAT;
    }
    tmp.hdr.version = version;
    tmp.hdr.len = len;

    DES4(tmp.flags);

    DESN(tmp.dest_cert, tmp.dest_cert_len);
    if (tmp.dest_cert == NULL) {
        iota_free(msg_bytes_cp);
        return IOTA_ERR_MALLOC_FAIL;
    }

    DESN(tmp.cert, tmp.cert_len);
    if (tmp.cert == NULL) {
        iota_free(msg_bytes_cp);
        iota_free(tmp.dest_cert);
        return IOTA_ERR_MALLOC_FAIL;
    }

    uint32_t unencrypted_len = (uint8_t*)p - msg_bytes_cp;
    uint8_t *decrypted = NULL;
    uint32_t decrypted_len;
    if (tmp.flags & IOTA_ENCRYPTED_FLAG) {
        // Invoke decryption function on encrypted part of msg
        if ((ret = iota_decrypt((uint8_t*)p, (uint32_t)(len - ((uint8_t*)p - msg_bytes_cp)),
                                iota_inst->cert, iota_inst->cert_len,
                                &decrypted,
                                &decrypted_len)) != IOTA_OK) {
            iota_free(msg_bytes_cp);
            iota_free(tmp.dest_cert);
            iota_free(tmp.cert);
            return ret;
        }
        uint8_t* new_msg_bytes = iota_malloc(unencrypted_len + decrypted_len);
        if (new_msg_bytes == NULL) {
            iota_free(tmp.dest_cert);
            iota_free(tmp.cert);
            iota_free(msg_bytes_cp);
            return IOTA_ERR_MALLOC_FAIL;
        }
        iota_memcpy(new_msg_bytes, msg_bytes_cp, unencrypted_len);
        iota_free(msg_bytes_cp);
        iota_memcpy(new_msg_bytes + unencrypted_len, decrypted, decrypted_len);
        msg_bytes_cp = new_msg_bytes;
        p = (uint32_t*)(msg_bytes_cp + unencrypted_len);
        iota_free(decrypted);
    }

    DES4_T(tmp.type, uint8_t);
    DES4_T(tmp.action, uint16_t);
    DES4(tmp.id);
    DES4_T(tmp.meas_type, uint8_t);
    DES4(tmp.ret);
    DESN(tmp.nonce, tmp.nonce_len);
    if (tmp.nonce == NULL) {
        iota_free(tmp.dest_cert);
        iota_free(tmp.cert);
        iota_free(msg_bytes_cp);
        return IOTA_ERR_MALLOC_FAIL;
    }

    DESN(tmp.dest_cert2, tmp.dest_cert2_len);
    if (tmp.dest_cert2 == NULL) {
        iota_free(tmp.dest_cert);
        iota_free(tmp.cert);
        iota_free(tmp.nonce);
        iota_free(msg_bytes_cp);
        return IOTA_ERR_MALLOC_FAIL;
    }

    DESN(tmp.data, tmp.data_len);
    if (tmp.data == NULL) {
        iota_free(tmp.dest_cert);
        iota_free(tmp.cert);
        iota_free(tmp.nonce);
        iota_free(tmp.dest_cert2);
        iota_free(msg_bytes_cp);
        return IOTA_ERR_MALLOC_FAIL;
    }

    uint8_t* signed_region_end = (uint8_t*)p;
    DESN(tmp.sig, tmp.sig_len);
    if (tmp.sig == NULL) {
        iota_free(tmp.dest_cert);
        iota_free(tmp.sig);
        iota_free(tmp.cert);
        iota_free(tmp.nonce);
        iota_free(tmp.dest_cert2);
        iota_free(tmp.data);
        iota_free(msg_bytes_cp);
        return IOTA_ERR_MALLOC_FAIL;
    }

    if ((tmp.flags & IOTA_SIGNED_FLAG) != 0) {
        uint8_t* signed_region_start = msg_bytes_cp + sizeof(uint32_t)*2;
        if ((ret = iota_signature_verify(signed_region_start,
                                         (uint32_t)(signed_region_end - signed_region_start),
                                         tmp.cert, tmp.cert_len,
                                         tmp.sig, tmp.sig_len))
                != IOTA_OK) {
            iota_free(tmp.dest_cert);
            iota_free(tmp.cert);
            iota_free(tmp.nonce);
            iota_free(tmp.dest_cert2);
            iota_free(tmp.data);
            iota_free(tmp.sig);
            iota_free(msg_bytes_cp);
            return ret;
        }
    }

    iota_memcpy(out, &tmp, sizeof(iota_msg));
    iota_free(msg_bytes_cp);
    return IOTA_OK;
}

char *iota_strerror(iota_ret err)
{
#ifndef NO_IOTA_STRERROR
    switch (err) {
    case IOTA_OK:
        return "iota success";
    case IOTA_ERR_NOT_READY:
        return "iota not initialized";
    case IOTA_ERR_BAD_INIT:
        return "bad arguments to iota_init";
    case IOTA_ERR_BAD_ID:
        return "request for non-existant measurement function";
    case IOTA_ERR_BAD_REQ:
        return "bad request";
    case IOTA_ERR_BAD_ARG:
        return "bad argument to measurement function";
    case IOTA_ERR_MALFORMAT:
        return "incorrectly-formatted serialized message";
    case IOTA_ERR_ENCRYPT_FAIL:
        return "failed to encrypt message";
    case IOTA_ERR_DECRYPT_FAIL:
        return "failed to decrypt message";
    case IOTA_ERR_VERIFY_FAIL:
        return "failed to verify message";
    case IOTA_ERR_SIGN_FAIL:
        return "failed to sign message";
    case IOTA_ERR_MALLOC_FAIL:
        return "malloc failure";
    case IOTA_ERR_MEAS:
        return "error during measurement";
    case IOTA_ERR_UNKNOWN:
        return "unknown error";
    default:
        return "unknown error type";
    }
#else
    return "";
#endif // NO_IOTA_STRERROR
}
