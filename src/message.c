#include "scep.h"


SCEP_ERROR scep_pkcsreq(
    SCEP *handle, X509_REQ *req, X509 *sig_cert, EVP_PKEY *sig_key,
        X509 *enc_cert, const EVP_CIPHER *enc_alg,
        PKCS7 **pkiMessage)
{
    BIO *databio = NULL;
    EVP_PKEY *req_pubkey = NULL;
    SCEP_ERROR error = SCEPE_OK;

#define OSSL_ERR(msg)                                   \
    do {                                                \
        error = SCEPE_OPENSSL;                          \
        ERR_print_errors(handle->configuration->log);   \
        scep_log(handle, FATAL, msg);                   \
        goto finally;                                   \
    } while(0)

    // TODO: verify that request contains required attributes

    databio = BIO_new(BIO_s_mem());
    if(!databio)
        OSSL_ERR("Could not create data BIO.\n");

    if(i2d_X509_REQ_bio(databio, req) <= 0)
        OSSL_ERR("Could not read request into data BIO.\n");

    req_pubkey = X509_REQ_get_pubkey(req);
    if(!req_pubkey)
        OSSL_ERR("Could not get public key from CSŖ.\n");

    error = scep_pkiMessage(
        handle, sig_cert, sig_key, req_pubkey, MESSAGE_TYPE_PKCSREQ,
        databio, enc_cert, enc_alg, pkiMessage);

finally:
    if(databio)
        BIO_free(databio);
    if(req_pubkey)
        EVP_PKEY_free(req_pubkey);
    return error;
#undef OSSL_ERR
}


SCEP_ERROR scep_pkiMessage(
        SCEP *handle, X509 *sig_cert, EVP_PKEY *sig_key,
        EVP_PKEY *req_pubkey,
        char *messageType, BIO *data,
        X509 *enc_cert, const EVP_CIPHER *enc_alg,
        PKCS7 **pkiMessage) {
    PKCS7 *p7 = NULL, *encdata = NULL;
    PKCS7_SIGNER_INFO *p7_signer_info = NULL;
    SCEP_ERROR error = SCEPE_OK;
    STACK_OF(X509) *enc_certs;
    BIO *pkcs7bio = NULL;
    char *transaction_id = NULL;
    ASN1_PRINTABLESTRING *asn1_transaction_id, *asn1_message_type, *asn1_sender_nonce;
    unsigned char sender_nonce[NONCE_LENGTH];

#define OSSL_ERR(msg)                                   \
    do {                                                \
        error = SCEPE_OPENSSL;                          \
        ERR_print_errors(handle->configuration->log);   \
        scep_log(handle, FATAL, msg);                   \
        goto finally;                                   \
    } while(0)

    p7 = PKCS7_new();
    if(p7 == NULL)
        OSSL_ERR("Could not create PKCS#7 data structure.\n");

    if(!PKCS7_set_type(p7, NID_pkcs7_signed)) 
        OSSL_ERR("Could not set PKCS#7 type.\n");

    p7_signer_info = PKCS7_add_signature(
        p7, sig_cert, sig_key, handle->configuration->sigalg);
    if(p7_signer_info == NULL)
        OSSL_ERR("Could not create new PKCS#7 signature.\n");

    /* transaction ID */
    if((error = scep_calculate_transaction_id(handle, req_pubkey, &transaction_id)) != SCEPE_OK) {
        scep_log(handle, FATAL, "Could create transaction ID.\n");
        goto finally;
    }

    asn1_transaction_id = ASN1_PRINTABLESTRING_new();
    if(asn1_transaction_id == NULL)
        OSSL_ERR("Could not create ASN1 TID object.\n");
    if(!ASN1_STRING_set(asn1_transaction_id, transaction_id, -1))
        OSSL_ERR("Could not set ASN1 TID object.\n");
    if(!PKCS7_add_signed_attribute(
            p7_signer_info, handle->oids.transId, V_ASN1_PRINTABLESTRING, 
            asn1_transaction_id))
        OSSL_ERR("Could not add attribute for transaction ID.\n");

    /* message type */
    asn1_message_type = ASN1_PRINTABLESTRING_new();
    if(asn1_message_type == NULL)
        OSSL_ERR("Could not create ASN1 message type object.\n");
    if(!ASN1_STRING_set(asn1_message_type, messageType, -1))
        OSSL_ERR("Could not set ASN1 message type object.\n");
    if(!PKCS7_add_signed_attribute(
            p7_signer_info, handle->oids.messageType, V_ASN1_PRINTABLESTRING,
            asn1_message_type))
        OSSL_ERR("Could not add attribute for message type.\n");

    /* sender nonce */
    if(RAND_bytes(sender_nonce, NONCE_LENGTH) == 0)
        OSSL_ERR("Could not generate random sender nonce.\n");
    asn1_sender_nonce = ASN1_OCTET_STRING_new();
    if(asn1_sender_nonce == NULL)
        OSSL_ERR("Could not create ASN1 sender nonce object.\n");
    if(!ASN1_OCTET_STRING_set(asn1_sender_nonce, sender_nonce, NONCE_LENGTH))
        OSSL_ERR("Could not set ASN1 sender nonce object.\n");
    if(!PKCS7_add_signed_attribute(
            p7_signer_info, handle->oids.senderNonce, V_ASN1_OCTET_STRING,
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
    if(!PKCS7_content_new(p7, NID_pkcs7_data))
        OSSL_ERR("Could not create inner PKCS#7 data structure.\n");
    pkcs7bio = PKCS7_dataInit(p7, NULL);
    if(!pkcs7bio)
        OSSL_ERR("Could not initialize PKCS#7 data.\n");
    if(!i2d_PKCS7_bio(pkcs7bio, encdata))
        OSSL_ERR("Could not write encdata to PKCS#7 BIO.\n");
    if(!PKCS7_dataFinal(p7, pkcs7bio))
        OSSL_ERR("Could not finalize PKCS#7 data.\n");

    *pkiMessage = p7;
finally:
    if(error != SCEPE_OK && p7)
        PKCS7_free(p7);
    if(pkcs7bio)
        BIO_free(pkcs7bio);
    if(transaction_id)
        free(transaction_id);
    return error;
#undef OSSL_ERR
}
