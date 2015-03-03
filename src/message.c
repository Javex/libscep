#include "scep.h"
SCEP_ERROR scep_p7_client_init(SCEP *handle, EVP_PKEY *req_pubkey, X509 *sig_cert, EVP_PKEY *sig_key, struct p7_data_t *p7data)
{
    SCEP_ERROR error = SCEPE_OK;
#define OSSL_ERR(msg)                                   \
    do {                                                \
        error = SCEPE_OPENSSL;                          \
        ERR_print_errors(handle->configuration->log);   \
        scep_log(handle, FATAL, msg);                   \
        goto finally;                                   \
    } while(0)

    p7data->p7 = PKCS7_new();
    if(p7data->p7 == NULL)
        OSSL_ERR("Could not create PKCS#7 data structure.\n");

    if(!PKCS7_set_type(p7data->p7, NID_pkcs7_signed))
        OSSL_ERR("Could not set PKCS#7 type.\n");

    p7data->signer_info = PKCS7_add_signature(
        p7data->p7, sig_cert, sig_key, handle->configuration->sigalg);
    if(p7data->signer_info == NULL)
        OSSL_ERR("Could not create new PKCS#7 signature.\n");

    /* transaction ID */
    if((error = scep_calculate_transaction_id(handle, req_pubkey, &p7data->transaction_id)) != SCEPE_OK) {
        scep_log(handle, FATAL, "Could create transaction ID.\n");
        goto finally;
    }

    /* sender nonce */
    if(RAND_bytes(p7data->sender_nonce, NONCE_LENGTH) == 0)
        OSSL_ERR("Could not generate random sender nonce.\n");

    /* Initialize content */
    if(!PKCS7_content_new(p7data->p7, NID_pkcs7_data))
        OSSL_ERR("Could not create inner PKCS#7 data structure.\n");
    p7data->bio = PKCS7_dataInit(p7data->p7, NULL);
    if(!p7data->bio)
        OSSL_ERR("Could not initialize PKCS#7 data.\n");

finally:
    if(error != SCEPE_OK) {
        if(p7data->p7)
            PKCS7_free(p7data->p7);
        if(p7data->bio)
            BIO_free(p7data->bio);
        if(p7data->transaction_id)
            free(p7data->transaction_id);
    }
    return error;
#undef OSSL_ERR
}

SCEP_ERROR scep_p7_final(SCEP *handle, struct p7_data_t *p7data, PKCS7 **p7)
{
    SCEP_ERROR error = SCEPE_OK;
#define OSSL_ERR(msg)                                   \
    do {                                                \
        error = SCEPE_OPENSSL;                          \
        ERR_print_errors(handle->configuration->log);   \
        scep_log(handle, FATAL, msg);                   \
        goto finally;                                   \
    } while(0)

    if(!PKCS7_dataFinal(p7data->p7, p7data->bio))
        OSSL_ERR("Could not finalize PKCS#7 data.\n");

    *p7 = p7data->p7;
finally:
    return error;
#undef OSSL_ERR
}

SCEP_ERROR scep_pkcsreq(
    SCEP *handle, X509_REQ *req, X509 *sig_cert, EVP_PKEY *sig_key,
        X509 *enc_cert, const EVP_CIPHER *enc_alg,
        PKCS7 **pkiMessage)
{
    BIO *databio = NULL;
    EVP_PKEY *req_pubkey = NULL;
    SCEP_ERROR error = SCEPE_OK;
    struct p7_data_t p7data;
    X509_NAME *subject;
    char *subject_str = NULL;
    int passwd_index;

#define OSSL_ERR(msg)                                   \
    do {                                                \
        error = SCEPE_OPENSSL;                          \
        ERR_print_errors(handle->configuration->log);   \
        scep_log(handle, FATAL, msg);                   \
        goto finally;                                   \
    } while(0)

    subject = X509_REQ_get_subject_name(req);
    subject_str = X509_NAME_oneline(subject, NULL, 0);
    if(!strlen(subject_str)) {
        scep_log(handle, ERROR, "Need a subject on CSR as required by SCEP protocol specification.\n");
        return SCEPE_INVALID_CONTENT;
    }
    scep_log(handle, INFO, "Certificate subject: %s\n", subject_str);
    free(subject_str);

    req_pubkey = X509_REQ_get_pubkey(req);
    if(!req_pubkey) {
        scep_log(handle, ERROR, "Need public key on CSR.\n");
        return SCEPE_INVALID_CONTENT;
    }

    passwd_index = X509_REQ_get_attr_by_NID(req, NID_pkcs9_challengePassword, -1);
    if(passwd_index == -1) {
        scep_log(handle, ERROR, "Need challenge password field on CSR.\n");
        return SCEPE_INVALID_CONTENT;
    }

    databio = BIO_new(BIO_s_mem());
    if(!databio)
        OSSL_ERR("Could not create data BIO.\n");

    if(i2d_X509_REQ_bio(databio, req) <= 0)
        OSSL_ERR("Could not read request into data BIO.\n");

    if((error = scep_p7_client_init(handle, req_pubkey, sig_cert, sig_key, &p7data)) != SCEPE_OK)
        goto finally;
    if((error = scep_pkiMessage(
            handle, MESSAGE_TYPE_PKCSREQ,
            databio, enc_cert, enc_alg, &p7data)) != SCEPE_OK)
        goto finally;
    if((error = scep_p7_final(handle, &p7data, pkiMessage)) != SCEPE_OK)
        goto finally;

finally:
    if(databio)
        BIO_free(databio);
    if(req_pubkey)
        EVP_PKEY_free(req_pubkey);
    return error;
#undef OSSL_ERR
}


SCEP_ERROR scep_pkiMessage(
        SCEP *handle,
        char *messageType, BIO *data,
        X509 *enc_cert, const EVP_CIPHER *enc_alg,
        struct p7_data_t *p7data) {
    PKCS7 *encdata = NULL;
    SCEP_ERROR error = SCEPE_OK;
    STACK_OF(X509) *enc_certs;
    ASN1_PRINTABLESTRING *asn1_transaction_id, *asn1_message_type, *asn1_sender_nonce;

#define OSSL_ERR(msg)                                   \
    do {                                                \
        error = SCEPE_OPENSSL;                          \
        ERR_print_errors(handle->configuration->log);   \
        scep_log(handle, FATAL, msg);                   \
        goto finally;                                   \
    } while(0)

    /* transaction ID */
    asn1_transaction_id = ASN1_PRINTABLESTRING_new();
    if(asn1_transaction_id == NULL)
        OSSL_ERR("Could not create ASN1 TID object.\n");
    if(!ASN1_STRING_set(asn1_transaction_id, p7data->transaction_id, -1))
        OSSL_ERR("Could not set ASN1 TID object.\n");
    if(!PKCS7_add_signed_attribute(
            p7data->signer_info, handle->oids.transId, V_ASN1_PRINTABLESTRING,
            asn1_transaction_id))
        OSSL_ERR("Could not add attribute for transaction ID.\n");

    /* message type */
    asn1_message_type = ASN1_PRINTABLESTRING_new();
    if(asn1_message_type == NULL)
        OSSL_ERR("Could not create ASN1 message type object.\n");
    if(!ASN1_STRING_set(asn1_message_type, messageType, -1))
        OSSL_ERR("Could not set ASN1 message type object.\n");
    if(!PKCS7_add_signed_attribute(
            p7data->signer_info, handle->oids.messageType, V_ASN1_PRINTABLESTRING,
            asn1_message_type))
        OSSL_ERR("Could not add attribute for message type.\n");

    /* sender nonce */
    asn1_sender_nonce = ASN1_OCTET_STRING_new();
    if(asn1_sender_nonce == NULL)
        OSSL_ERR("Could not create ASN1 sender nonce object.\n");
    if(!ASN1_OCTET_STRING_set(asn1_sender_nonce, p7data->sender_nonce, NONCE_LENGTH))
        OSSL_ERR("Could not set ASN1 sender nonce object.\n");
    if(!PKCS7_add_signed_attribute(
            p7data->signer_info, handle->oids.senderNonce, V_ASN1_OCTET_STRING,
            asn1_sender_nonce))
        OSSL_ERR("Could not add attribute for sender nonce.\n");

    /* encrypt data */
    // since we currently are a client, we always have data
    // however, if we want to support server in the future as well
    // we sould make data optional.

    // certificate to encrypt data with
    enc_certs = sk_X509_new_null();
    if(!enc_certs)
        OSSL_ERR("Could not create enc cert stack.\n");
    if(!sk_X509_push(enc_certs, enc_cert))
        OSSL_ERR("Could not push enc cert onto stack.\n");

    encdata = PKCS7_encrypt(enc_certs, data, enc_alg, PKCS7_BINARY);
    if(!encdata)
        OSSL_ERR("Could not encrypt data.\n");

    // put encrypted data into p7
    if(!i2d_PKCS7_bio(p7data->bio, encdata))
        OSSL_ERR("Could not write encdata to PKCS#7 BIO.\n");

finally:
    return error;
#undef OSSL_ERR
}
