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

#include "libiota.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "helper.h"

#include "aes.h"
#include "platform.h"
#include "sha256.h"
#include "ssl.h"
#include "rsa.h"
#include "error.h"
#include "pk.h"
#include "iota_certs.h"
#include "ns_certs.h"
#include "entropy.h"
#include "ctr_drbg.h"
#include "cipher.h"

// TODO REMOVE THIS - debugging only

int sign_measurement(unsigned char * meas_start, unsigned int meas_len, const unsigned char * priv_key, 
	  unsigned int priv_key_len, unsigned char * sig){

		mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
		const char *pers = "mbedtls_pk_sign";
		mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );
		mbedtls_pk_context pk;
		void* pk_tracker;
		pk_tracker = &pk;
		size_t olen = 0;
			
    mbedtls_pk_init( &pk );
			
		int ret = mbedtls_pk_parse_key(&pk, priv_key, priv_key_len, NULL, 0);
		if(ret != 0){
			  mbedtls_printf( " failed\n  ! mbedtls_pk_sign returned -0x%04x\n", (unsigned int) -ret );
        return IOTA_ERR_SIGN_FAIL;
    }

		mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk.pk_ctx;
    if( (ret = mbedtls_rsa_check_privkey(rsa) ) != 0){
				mbedtls_printf( " failed\n  ! mbedtls_pk_sign returned -0x%04x\n", (unsigned int) -ret );
        return IOTA_ERR_SIGN_FAIL;
    }
		
		unsigned char hash[32] = {0};
		
    ret = mbedtls_md( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), meas_start, meas_len, hash);
    if (ret != 0){
				mbedtls_printf( " failed\n  ! mbedtls_pk_sign returned -0x%04x\n", (unsigned int) -ret );
        return IOTA_ERR_SIGN_FAIL;
    }
		
		if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, myrand, &entropy,
				(unsigned char *) pers, strlen( pers ) ) ) != 0 )
		{
				printf( " failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret );
				mbedtls_entropy_free( &entropy );
				mbedtls_ctr_drbg_free( &ctr_drbg );
				return IOTA_ERR_SIGN_FAIL;
		}
		
		if (( ret = mbedtls_rsa_rsassa_pkcs1_v15_sign( rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 20, hash, sig)) != 0 )
		{		
        mbedtls_printf( " failed\n  ! mbedtls_pk_sign returned -0x%04x\n", (unsigned int) -ret );
        return IOTA_ERR_SIGN_FAIL;
    }
		
		mbedtls_pk_free(&pk); 
		
		return 0;
}
		
iota_ret iota_sign(uint8_t *buf_in, uint32_t buf_sz,
                   uint8_t **sig, uint32_t *sig_len) 
{
	*sig = malloc(256);
	if (*sig == NULL) return IOTA_ERR_MALLOC_FAIL;
	if (sign_measurement((unsigned char*)buf_in, buf_sz,  (const unsigned char*) ns_privkey_pem, ns_privkey_pem_sz, *sig) != 0)
		return IOTA_ERR_SIGN_FAIL;
	*sig_len = 256;
	return IOTA_OK;
}

iota_ret iota_decrypt(uint8_t *in, uint32_t in_len,
                      uint8_t const* cert, uint32_t cert_len,
                      uint8_t **out, uint32_t *out_len) {
    // cert, cert_len are ignored because we only have one private
    // key.  if you have multiple contexts serviced by the library,
    // use cert to determine which key to use.
    
    // first bytes are encrypted with our public key
    int rsa_size = 256;
		int ret;
	  mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
	  const char *pers = "mbedtls_pk_decrypt";
	  size_t olen;
	  mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
	  												
		mbedtls_pk_context pk_s;
		mbedtls_pk_context pk_ns;
		unsigned char buf_key[52];
		unsigned char* enc_pv_key;
		mbedtls_x509_crt cert_chain;
														
    if (in_len < rsa_size) {
        return IOTA_ERR_DECRYPT_FAIL;
    }
    
		uint8_t *private_key;
		int private_key_sz = 0;
		
		enc_pv_key = malloc(rsa_size);
		memcpy(enc_pv_key, in, rsa_size);	
		
		if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, myrand,
                                       &entropy, (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
			 mbedtls_printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n",
                        (unsigned int) -ret );
			 mbedtls_pk_free(&pk_s);
			 mbedtls_pk_free(&pk_ns);
		   mbedtls_entropy_free( &entropy );
			 mbedtls_ctr_drbg_free( &ctr_drbg );
			 iota_free(*out);
			 *out = NULL;
			 *out_len = 0;
			 return IOTA_ERR_DECRYPT_FAIL;
		}
		
		mbedtls_x509_crt_init( &cert_chain );
		
		if( ( ret = mbedtls_x509_crt_parse( &cert_chain, cert, cert_len ) ) != 0 )
		{
			 mbedtls_printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n",
                        (unsigned int) -ret );
			  mbedtls_pk_free(&cert_chain.pk);
				mbedtls_entropy_free( &entropy );
				mbedtls_ctr_drbg_free( &ctr_drbg );
				iota_free(*out);
				*out = NULL;
				*out_len = 0;
				return IOTA_ERR_DECRYPT_FAIL;
		}
		
  	mbedtls_pk_init(&pk_s);
		mbedtls_pk_init(&pk_ns);
		
		ret = mbedtls_pk_parse_key(&pk_s, (const unsigned char *)tz_privkey_pem,
                                   tz_privkey_pem_sz, NULL, 0);
		
		ret = mbedtls_pk_parse_key(&pk_ns, (const unsigned char *)ns_privkey_pem,
                                   ns_privkey_pem_sz, NULL, 0);
		
		if( ( ret = mbedtls_pk_check_pair( &cert_chain.pk, &pk_s  ) ) == 0 )
		{
				if( ( ret = mbedtls_pk_decrypt(&pk_s, enc_pv_key, rsa_size, buf_key, &olen, rsa_size,
													mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
						{
								mbedtls_printf( " failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n",
											(unsigned int) -ret );
								mbedtls_pk_free(&pk_s);
								mbedtls_entropy_free( &entropy );
								mbedtls_ctr_drbg_free( &ctr_drbg );
								iota_free(*out);
								*out = NULL;
								*out_len = 0;
								return IOTA_ERR_DECRYPT_FAIL;
						}			
		}
		
		if( ( ret = mbedtls_pk_check_pair( &cert_chain.pk, &pk_ns  ) ) == 0 )
		{
				if( ( ret = mbedtls_pk_decrypt(&pk_ns, enc_pv_key, rsa_size, buf_key, &olen, rsa_size,
													mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
						{
								mbedtls_printf( " failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n",
											(unsigned int) -ret );
								mbedtls_pk_free(&pk_ns);
								mbedtls_entropy_free( &entropy );
								mbedtls_ctr_drbg_free( &ctr_drbg );
								iota_free(*out);
								*out = NULL;
								*out_len = 0;
								return IOTA_ERR_DECRYPT_FAIL;
						}			
		}
		
		mbedtls_pk_free(&pk_ns);
		
		mbedtls_pk_free(&pk_s);
		
    uint8_t* key = &(buf_key[0]);
    uint8_t* iv = &(buf_key[32]);
		uint32_t in_size;
		
		in_size = buf_key[51];
		in_size = (in_size << 8) + buf_key[50];
		in_size = (in_size << 8) + buf_key[49];
		in_size = (in_size << 8) + buf_key[48];
		
		// decrypt the rest
    if (!((*out) = iota_malloc(in_len - rsa_size))) {
        return IOTA_ERR_MALLOC_FAIL;
    }
		
		uint8_t* out_data = *out + rsa_size;
		
		mbedtls_aes_context aes;
		
		mbedtls_aes_init(&aes);

		if ( ( ret = mbedtls_aes_setkey_dec( &aes, key, 256 ) ) != 0 )
		{
				mbedtls_aes_free(&aes);
				mbedtls_printf( " failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n",
											(unsigned int) -ret );
				mbedtls_pk_free(&pk_ns);
				mbedtls_entropy_free( &entropy );
				mbedtls_ctr_drbg_free( &ctr_drbg );
				iota_free(*out);
				*out = NULL;
				*out_len = 0;
				return IOTA_ERR_DECRYPT_FAIL;
		}
    
		if ( ( ret = mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, in_len - rsa_size, iv, in + rsa_size, out_data ) ) != 0)
		{
				mbedtls_aes_free(&aes);
				mbedtls_printf( " failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n",
											(unsigned int) -ret );
				mbedtls_pk_free(&pk_ns);
				mbedtls_entropy_free( &entropy );
				mbedtls_ctr_drbg_free( &ctr_drbg );
				iota_free(*out);
				*out = NULL;
				*out_len = 0;
				return IOTA_ERR_DECRYPT_FAIL;
		}
		
		iota_memcpy(*out, out_data, in_size);
		
		*out_len = in_size;

    mbedtls_aes_free(&aes);
    return IOTA_OK;
}

#if defined(MBEDTLS_PKCS1_V15)
static int myrand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = (unsigned char)rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif

    return( 0 );
}
#endif 

iota_ret iota_encrypt(uint8_t *in, uint32_t in_len,
                      uint8_t const* cert, uint32_t cert_len,
                      uint8_t **out, uint32_t *out_len)
{
    int ret;	  
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
	  const char *pers = "mbedtls_pk_encrypt";
	  mbedtls_x509_crt cert_chain;
	  size_t olen;
	  mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
	  mbedtls_x509_crt_init( &cert_chain );
	  uint8_t key_iv[52]; // 32-byte key, 16-byte iv
    	
	  if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, myrand, &entropy,
				(unsigned char *) pers, strlen( pers ) ) ) != 0 )
		{
				printf( " failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret );
				mbedtls_pk_free(&cert_chain.pk);
				mbedtls_entropy_free( &entropy );
				mbedtls_ctr_drbg_free( &ctr_drbg );
				iota_free(*out);
				*out = NULL;
				*out_len = 0;
				return IOTA_ERR_ENCRYPT_FAIL;
		}

		if( ( ret = mbedtls_ctr_drbg_random( &ctr_drbg, key_iv, 48 ) ) != 0 )
		{
				printf( " failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret );
				mbedtls_pk_free(&cert_chain.pk);
				mbedtls_entropy_free( &entropy );
				mbedtls_ctr_drbg_free( &ctr_drbg );
				iota_free(*out);
				*out = NULL;
				*out_len = 0;
				return IOTA_ERR_ENCRYPT_FAIL;
		}
	
	  if( ( ret = mbedtls_x509_crt_parse( &cert_chain, cert, cert_len ) ) != 0 )
		{
			 mbedtls_printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n",
                        (unsigned int) -ret );
			  mbedtls_pk_free(&cert_chain.pk);
				mbedtls_entropy_free( &entropy );
				mbedtls_ctr_drbg_free( &ctr_drbg );
				iota_free(*out);
				*out = NULL;
				*out_len = 0;
				return IOTA_ERR_ENCRYPT_FAIL;
		}
		
		mbedtls_rsa_context *rsa = mbedtls_pk_rsa(cert_chain.pk);
		ret = mbedtls_rsa_complete( rsa );
		ret = mbedtls_rsa_check_pubkey(rsa);
		
		uint8_t * key = &(key_iv[0]);
    uint8_t * iv =  &(key_iv[32]);
		key_iv[48] = (uint8_t)(in_len >>  0);
		key_iv[49] = (uint8_t)(in_len >>  8);
		key_iv[50] = (uint8_t)(in_len >>  16);
		key_iv[51] = (uint8_t)(in_len >>  24);
		
	  int rsa_size = rsa->len;
    uint8_t* ep_key_iv = iota_malloc((size_t)rsa_size);
    if (ep_key_iv == NULL) {
        mbedtls_x509_crt_free(&cert_chain);
        return IOTA_ERR_MALLOC_FAIL;
    }
   		
    unsigned char buf[rsa_size];
		
		if( ( ret = mbedtls_pk_encrypt(&cert_chain.pk, key_iv, sizeof(key_iv),
                            buf, &olen, sizeof(buf),
                            mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
			{
				mbedtls_x509_crt_free(&cert_chain);
        return IOTA_ERR_ENCRYPT_FAIL;
			}
			
		mbedtls_x509_crt_free(&cert_chain);
			
	  //the aes_cbc in buffer size must be multiple of 16
		int out16_size;
		out16_size = in_len-1;
		out16_size = out16_size >> 4;
		out16_size++;
		out16_size = out16_size << 4;
			
	  // write out encrypted symmetric key and IV
    //*out = iota_malloc(in_len + olen + 16);
		*out = iota_malloc(out16_size + olen);
    if (*out == NULL) {
        iota_free(ep_key_iv);
        return IOTA_ERR_ENCRYPT_FAIL;
    }
    iota_memcpy(*out, buf, olen);
    iota_free(ep_key_iv);
		
		uint8_t* out_data = *out + rsa_size;
		
    // encrypt user data with symmetric key and IV and append to out
		mbedtls_aes_context aes;
				
		mbedtls_aes_init(&aes);

		if ( ( ret = mbedtls_aes_setkey_enc( &aes, key, 256 ) ) != 0 )
		{
			mbedtls_aes_free(&aes);
			mbedtls_pk_free(&cert_chain.pk);
			mbedtls_entropy_free( &entropy );
			mbedtls_ctr_drbg_free( &ctr_drbg );
			iota_free(*out);
			*out = NULL;
			*out_len = 0;
			return IOTA_ERR_ENCRYPT_FAIL;
			
		}
		
		if ( ( mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, out16_size, iv, in, out_data ) ) != 0)
		{
			mbedtls_aes_free(&aes);
			mbedtls_pk_free(&cert_chain.pk);
			mbedtls_entropy_free( &entropy );
			mbedtls_ctr_drbg_free( &ctr_drbg );
			iota_free(*out);
			*out = NULL;
			*out_len = 0;
			return IOTA_ERR_ENCRYPT_FAIL;
			
		}
		
		*out_len = out16_size + olen; //check this output size
		
		mbedtls_aes_free(&aes);
    mbedtls_pk_free(&cert_chain.pk);
		mbedtls_entropy_free( &entropy );
    mbedtls_ctr_drbg_free( &ctr_drbg );
		
		return IOTA_OK;	
}

iota_ret iota_signature_verify(uint8_t *buf, uint32_t buf_sz,
                               uint8_t *cert, uint32_t cert_sz,
                               uint8_t *sig, uint32_t sig_sz)
{
    int ret;
	  mbedtls_x509_crt cert_chain;
	  mbedtls_x509_crt_init( &cert_chain );
	  if( ( ret = mbedtls_x509_crt_parse( &cert_chain, cert, cert_sz ) ) != 0 )
		{
			  mbedtls_printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n",
                        (unsigned int) -ret );
			  mbedtls_pk_free(&cert_chain.pk);
				return IOTA_ERR_VERIFY_FAIL;
		}	

    if (mbedtls_pk_verify(&cert_chain.pk, MBEDTLS_MD_SHA256,
                          (const unsigned char*)buf, buf_sz,
                          (const unsigned char*)sig, sig_sz) == 0) {
        ret = IOTA_OK;
    }

    return ret;
}
