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

/*! \file libiota.h
 * `libiota` header exposing all needed structs, enumerations, and functions
 */

#ifndef _IOTA_H
#define _IOTA_H

#include <stdint.h>
#include <stdlib.h>

/*! Version of `libiota` messages.
 */
#define IOTA_VERSION 1

/*! Length of function name field
 */
#define IOTA_MEAS_FUNC_NAME_LEN 32

/*! Flag indicating message is encrypted
 */
#define IOTA_ENCRYPTED_FLAG 1 << 0

/*! Flag indicating message is signed
 */
#define IOTA_SIGNED_FLAG 1 << 1

/*! Malloc function to use for dynamic allocation in libiota
 */
#define iota_malloc malloc

/*! Realloc function to use
 */
#define iota_realloc realloc

/*! Memcpy function to use
 */
#define iota_memcpy memcpy

/*! Memset function to use
 */
#define iota_memset memset

/*! Free function to use
 */
#define iota_free free

/*! `libiota` return values.
 */
typedef enum iota_ret {
    IOTA_OK, /*!< success */
    IOTA_ERR_NOT_READY, /*!< iota object not in ready state */
    IOTA_ERR_BAD_INIT, /*!< Bad arguments for initializing iota */
    IOTA_ERR_BAD_ID, /*!< Bad measurement fucntion ID in request */
    IOTA_ERR_BAD_REQ, /*!< Bad request */
    IOTA_ERR_BAD_ARG, /*!< Bad argument to measurement function */
    IOTA_ERR_MALFORMAT, /*!< Message not properly formatted */
    IOTA_ERR_ENCRYPT_FAIL, /*!< Failure while trying to encrypt message */
    IOTA_ERR_DECRYPT_FAIL, /*!< Failure while trying to decrypt message */
    IOTA_ERR_VERIFY_FAIL, /*!< Failure while trying to verify message */
    IOTA_ERR_SIGN_FAIL, /*!< Failure while trying to sign message */
    IOTA_ERR_MALLOC_FAIL, /*!< Failure while trying to malloc */
    IOTA_ERR_MEAS, /*!< Failure during measurement */
    IOTA_ERR_UNKNOWN /*!< Failure for unknown reason */
} iota_ret;

/*! Types of measurement functions.
 */
typedef enum iota_meas_type {
    IOTA_MEAS_HASH, /*!< Hash of memory */
    IOTA_MEAS_GLOBAL, /*!< Measurement of global state */
    IOTA_MEAS_TEST, /*!< Test measurement */
    IOTA_MEAS_MISC /*!< Other, misc type of measurement */
} iota_meas_type;

/*! Actions a request can ask for.
 */
typedef enum iota_action {
    IOTA_ACTION_MEAS, /*!< Invoke a specific measurement function */
    IOTA_ACTION_LIST /*!< Get a list of available measurement functions */
} iota_action;

/*! Message types.
 */
typedef enum iota_msg_type {
    IOTA_REQUEST, /*!< Request message */
    IOTA_RESPONSE, /*!< Response message */
} iota_msg_type;

/*! libiota message header; this section of the iota_msg is sent in plain text
 */
typedef struct __attribute__ ((__packed__)) iot_msg_hdr {
    uint32_t version; /*!< Version of message */
    uint32_t len; /*!< Only used for serialization/deserialization. Full length of the serialized message in bytes. */
} iota_msg_hdr;

/*! libiota message; header is sent plaintext, remaining fields are
encrypted if encryption is enabled
 */
typedef struct iota_msg {
    /* These fields are never encrypted. */
    iota_msg_hdr hdr; /*!< Message header */
    uint32_t flags; /*!< Set of flags for message */

    /* Fields from here forward are signed (after serialization) */
    uint32_t dest_cert_len; /*!< Length of dest_cert in bytes */
    uint8_t *dest_cert; /*!< Certificate of addressee, unencrypted */
    uint32_t cert_len; /*!< Length of cert in bytes */
    uint8_t *cert; /*!< Certificate of sender */

    /* The subsequent fields are all encrypted after serialization if
       encryption is enabled. */
    uint8_t type; /*!< Message type */
    uint8_t action; /*!< Action */
    uint16_t id; /*!< Measurement function ID */
    uint8_t meas_type; /*!< Measurement function type */
    uint8_t ret; /*!< Return code */
    uint32_t nonce_len; /*!< Length of nonce in bytes */
    uint8_t *nonce; /*!< Nonce */
    uint32_t dest_cert2_len; /*!< Length of dest_cert in bytes */
    uint8_t *dest_cert2; /*!< Hash of the certificate of the addressee */
    uint32_t data_len; /*!< Length of unencrypted message data */
    uint8_t *data; /*!< Message data */
    /* End of signed fields */

    uint32_t sig_len; /*!< Length of sig in bytes */
    uint8_t *sig; /*!< Signature */
    /* End of encrypted fields */

} iota_msg;

/*! libiota measurement function signature.
 *
 * Measurement functions can expect that any arguments to the function received
 * from a request iota_msg will be placed at arg and arg_len set to the length
 * of the argument buffer.
 *
 * \param arg Pointer to argument buffer.
 * \param arg_len Length of arg buffer.
 * \param meas Pointer to output buffer, should be allocated and set by
               implementation.
 * \param meas_len Pointer to measurement length, should be set by
                   implementation.
 *
 * \return IOTA_OK if successful.
 */
typedef iota_ret (*iota_func)(uint8_t *arg, uint32_t arg_len,
                              uint8_t **meas, uint32_t *meas_len);

/*! Signature for custom free callback.
 *
 * \param ptr Pointer to free.
 */
typedef void (*iota_custom_free)(void* ptr);

/*! Struct for holding measurement function.
 */
typedef struct iota_meas_func {
    iota_meas_type type; /*!< Function type */
    char name[IOTA_MEAS_FUNC_NAME_LEN]; /*!< Function name */
    iota_func func; /*!< Pointer to function */
    iota_custom_free free_func; /*!< Custom free function (may be NULL) */
} iota_meas_func;

/*! Struct for an entry in a list indicating which measurement functions are
 *  available to an iota instance.
 */
typedef struct __attribute__ ((__packed__)) iota_list_entry {
    uint16_t id; /*!< Unique ID for the function */
    char name[IOTA_MEAS_FUNC_NAME_LEN]; /*!< Function name */
    uint8_t type; /*!< Function type */
} iota_list_entry;

/*! Main libiota structure.
 */
typedef struct iota {
    iota_meas_func const *meas_funcs; /*!< Array of meas_funcs */
    uint32_t flags; /*!< Flags for requring requests to be signed/encrypted */
    uint16_t num_funcs; /*!< Number of functions */
    uint8_t *cert; /*!< Buffer containing public certificate for this device */
    uint32_t cert_len; /*!< Size of the cert, in bytes */
} iota;

/*! Initialize an iota structure.
 *
 * \param iota iota instance to initialize.
 * \param funcs Null-terminated array of measurement functions to use.
 * \param flags Flags for requiring requests to be signed/encrypted.
 * \param cert Buffer containing the public certificate for this iota instance; if signing and encryption are both disabled, pass NULL.
 * \param cert_len Length of the certificate buffer in bytes, or 0 if NULL.
 * \param cert Buffer containing the public key for this iota instance; if signing and encryption are both disabled, pass NULL.
 * \param cert_len Length of the public key buffer in bytes, or 0 if NULL.
 *
 * \return IOTA_OK if successful or IOTA_ERR_BAD_INIT on bad arguments.
 */
iota_ret iota_init(iota *iota, const iota_meas_func *funcs, uint32_t flags,
                   uint8_t *cert, uint32_t cert_len);

/*! Perform the operation requested and generate a response. It is the
 *  caller's responsibility to validate that the message is correctly
 *  addressed and signed.
 *
 * The output response must be freed using `iota_msg_deinit` after use.
 *
 * \param iota iota instance to use to handle request (must be initialized).
 * \param req Pointer to input request
 * \param resp Pointer to output response, will be allocated and set
               during response generation.
 *
 * \return IOTA_OK if successful.
 */
iota_ret iota_do(iota *iota, const iota_msg *req, iota_msg **resp);

/*! Initialize an IOTA request to send to an iota instance.
 *
 * This request must be freed using `iota_msg_deinit` after use.
 *
 * \param iota Associated IoTA instance for message
 * \param msg Pointer to output buffer, will be allocated and set.
 * \param flags Flags to set in message
 * \param action Request action to take.
 * \param id ID of function to request.
 * \param arg Pointer to argument buffer, will be set as data for request.
 * \param arg_len Length of arg buffer.
 * \param nonce Pointer to buffer containing nonce for request
 * \param nonce_len Length of nonce buffer
 * \param dest_cert Buffer containing certificate of the destination
 * \param dest_cert_len Length of dest_cert  buffer, in bytes
 *
 * \return IOTA_OK if successful.
 */
iota_ret iota_req_init(iota* iota, iota_msg **msg, uint32_t flags,
                       iota_action action, uint16_t id, uint8_t *arg,
                       uint32_t arg_len,
                       uint8_t *nonce, uint32_t nonce_len,
                       uint8_t *dest_cert, uint32_t dest_cert_len);

/*! Deinitialize an IOTA message.
 *
 * \param msg Pointer to pointer to message to deinitialize. Its children will be freed, then the iota_msg itself.
 */
void iota_msg_deinit(iota_msg **msg);


/*! Get a string representation of a libiota return code.
 *
 * \param err iota_ret error code to get string representation of.
 *
 * \return String representation of error code.
 */
char *iota_strerror(iota_ret err);

/*! Serialize an iota_msg into a flat buffer.
 * \param iota_inst The current IoTA instance
 * \param msg An iota_msg instance, assumed to contain valid pointers to data fields
 * \param outbuf Will point to a newly-malloced buffer containing the serialized IOTA message on success, or set to NULL on failure.
 * \param outbuf_len Length of outbuf.
 *
 * \return IOTA_OK if no errors.
 */
iota_ret  iota_serialize(iota *iota_inst, iota_msg* msg,
                         uint8_t** outbuf, uint32_t *outbuf_len);

/*! Deserialize an iota_msg (possibly encrypted) from a flat buffer
 *  into a usable structure.  It will be decrypted if necessary.  Make
 *  sure that the message is completely downloaded (use the
 *  unencrypted bytes in the header) and that the addressee is
 *  correct.  This call will fail if decryption fails.
 *
 * \param iota_inst Initialized IoTA instance
 * \param msg_bytes A stream of bytes containing the IoTA
 * message. Should be completely downloaded before this function is
 * called (use the header bytes, which are unencrypted, to determine
 * message length.)
 * \param msg_bytes_sz The size of the msg_bytes.
 * \param out Must be allocated already. Fields will be populated with newly-malloced memory.
 *
 * \return IOTA_OK if no errors.
 */
iota_ret iota_deserialize(iota *iota_inst,
                          uint8_t* msg_bytes, uint32_t msg_bytes_sz,
                          iota_msg *out);


/******************** STUB FUNCTIONS *************************
 *
 *  The following are not implementedin libiota and are left *
 *  to the implementor of the iota-enabled device            */

/*! Stub for message signging
 *
 * \param buf_in Buffer of data to sign
 * \param buf_sz Length of buf_in in bytes
 * \param sig Output buffer for signature (must be allocated).
 * \param sig_len Must be set to sig length.
 *
 * \return IOTA_OK if no errors.
 */
iota_ret iota_sign(uint8_t *buf_in, uint32_t buf_sz,
                   uint8_t **sig, uint32_t *sig_len);

/*! Stub for signature verification.
 *
 * \param buf Buffer containing signed data
 * \param buf_sz Size of buf in bytes
 * \param cert Certificate of signer
 * \param cert_sz Size of cert in bytes
 * \param sig Signature on buf
 * \param sig_sz Size of sig
 *
 * \return IOTA_OK if the signature matches the expected given the
 * data and certificate, IOTA_VERIFY_FAIL if signature does not match.
 * Return other error if execution is impossible (due to e.g. malloc
 * failure).
 */
iota_ret iota_signature_verify(uint8_t *buf, uint32_t buf_sz,
                               uint8_t *cert, uint32_t cert_sz,
                               uint8_t *sig, uint32_t sig_sz);

/*! Function used to encrypt data
 *
 * Must set output pointer to encrypted buffer and out_len to length of
 * encrypted buffer. Encrypted buffer length must be equal to input buffer
 * length.
 *
 * \param in Input buffer to encrypt.
 * \param in_len Length of in.
 * \param cert Certificate to use for encrypting the data.
 * \param cert_len Length of certificate.
 * \param out Output buffer for cyphertext of in.
 * \param out_len Output pointer to length of out (must equal in_len).
 *
 * \return IOTA_OK if no errors.
 */
iota_ret iota_encrypt(uint8_t *in, uint32_t in_len,
                      uint8_t const* cert, uint32_t cert_len,
                      uint8_t **out, uint32_t *out_len);

/*! Function used to decrypt data.
 *
 * Must set output pointer to decrypted buffer and out_len to length of
 * decrypted buffer. Decrypted buffer length must be equal to input buffer
 * length.
 *
 * \param in Input cyphertext buffer to decrypt.
 * \param in_len Length of in.
 * \param cert Certificate to use for encrypting the data.
 * \param cert_len Length of certificate.
 * \param out Output buffer for decrypted plaintext of in.
 * \param out_len Output pointer to length of out (must equal in_len).
 *
 * \return IOTA_OK if no errors.
 */
iota_ret iota_decrypt(uint8_t *in, uint32_t in_len,
                      uint8_t const* cert, uint32_t cert_len,
                      uint8_t **out, uint32_t *out_len);

#endif //_IOTA_H
