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
        
    PKCS7_add_certificate(p7data->p7, sig_cert);

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
    if(req_pubkey)  // needed?
        EVP_PKEY_free(req_pubkey);
    return error;
#undef OSSL_ERR
}

SCEP_ERROR scep_get_cert_initial(
        SCEP *handle, X509_REQ *req, X509 *sig_cert, EVP_PKEY *sig_key,
        X509 *cacert, X509 *enc_cert, const EVP_CIPHER *enc_alg,
        PKCS7 **pkiMessage)
{

    SCEP_ERROR error = SCEPE_OK;
    struct p7_data_t p7data;
    EVP_PKEY *req_pubkey = NULL;
    PKCS7_ISSUER_AND_SUBJECT *ias;
    unsigned char *ias_data = NULL;
    int ias_data_size;
    BIO *databio;
    char *subject_str = NULL, *issuer_str = NULL;

#define OSSL_ERR(msg)                                   \
    do {                                                \
        error = SCEPE_OPENSSL;                          \
        ERR_print_errors(handle->configuration->log);   \
        scep_log(handle, FATAL, msg);                   \
        goto finally;                                   \
    } while(0)

    req_pubkey = X509_REQ_get_pubkey(req);
    if(!req_pubkey) {
        scep_log(handle, ERROR, "Need public key on CSR.\n");
        return SCEPE_INVALID_CONTENT;
    }

    ias = PKCS7_ISSUER_AND_SUBJECT_new();
    if(!ias)
        OSSL_ERR("Could not create new issuer and subject structure.\n");

    ias->subject = X509_REQ_get_subject_name(req);
    if(!ias->subject)
        OSSL_ERR("Could not get subject from request.\n");
    subject_str = X509_NAME_oneline(ias->subject, NULL, 0);
    scep_log(handle, INFO, "Request subject is %s\n", subject_str);

    ias->issuer = X509_get_issuer_name(cacert);
    if(!ias->issuer)
        OSSL_ERR("Could not get issuer name for CA cert.\n");
    issuer_str = X509_NAME_oneline(ias->issuer, NULL, 0);
    scep_log(handle, INFO, "Issuer Name is %s\n", issuer_str);

    ias_data_size = i2d_PKCS7_ISSUER_AND_SUBJECT(ias, &ias_data);
    if(!ias_data_size)
        OSSL_ERR("Could not extract issuer and subject data.\n");

    databio = BIO_new(BIO_s_mem());
    if(!databio)
        OSSL_ERR("Could not create data BIO.\n");

    if(!BIO_write(databio, ias_data, ias_data_size))
        OSSL_ERR("Could not write issuer and subject data into BIO.\n");

    if((error = scep_p7_client_init(handle, req_pubkey, sig_cert, sig_key, &p7data)))
        goto finally;
    if((error = scep_pkiMessage(
            handle, MESSAGE_TYPE_GETCERTINITIAL, databio, enc_cert, enc_alg, &p7data)) != SCEPE_OK)
        goto finally;
    if((error = scep_p7_final(handle, &p7data, pkiMessage)) != SCEPE_OK)
        goto finally;

finally:
    if(databio)
        BIO_free(databio);
    return error;
#undef OSSL_ERR
}

static SCEP_ERROR _scep_get_cert_or_crl(
        SCEP *handle, X509_REQ *req, X509 *sig_cert, EVP_PKEY *sig_key,
        X509 *req_cert, X509 *enc_cert, const EVP_CIPHER *enc_alg,
        char *messageType, PKCS7 **pkiMessage)
{

    SCEP_ERROR error = SCEPE_OK;
    struct p7_data_t p7data;
    EVP_PKEY *req_pubkey = NULL;
    PKCS7_ISSUER_AND_SERIAL *ias;
    unsigned char *ias_data = NULL;
    int ias_data_size;
    BIO *databio;
    char *issuer_str = NULL;

#define OSSL_ERR(msg)                                   \
    do {                                                \
        error = SCEPE_OPENSSL;                          \
        ERR_print_errors(handle->configuration->log);   \
        scep_log(handle, FATAL, msg);                   \
        goto finally;                                   \
    } while(0)

    req_pubkey = X509_REQ_get_pubkey(req);
    if(!req_pubkey) {
        scep_log(handle, ERROR, "Need public key on CSR.\n");
        return SCEPE_INVALID_CONTENT;
    }

    ias = PKCS7_ISSUER_AND_SERIAL_new();
    if(!ias)
        OSSL_ERR("Could not create new issuer and subject structure.\n");

    ias->serial = X509_get_serialNumber(req_cert);
    if(!ias->serial)
        OSSL_ERR("Could not get serial from CA cert.\n");
    // subject_str = X509_NAME_oneline(ias->subject, NULL, 0);
    // scep_log(handle, INFO, "Request subject is %s\n", subject_str);

    ias->issuer = X509_get_issuer_name(req_cert);
    if(!ias->issuer)
        OSSL_ERR("Could not get issuer name for CA cert.\n");
    issuer_str = X509_NAME_oneline(ias->issuer, NULL, 0);
    scep_log(handle, INFO, "Issuer Name is %s\n", issuer_str);

    ias_data_size = i2d_PKCS7_ISSUER_AND_SERIAL(ias, &ias_data);
    if(!ias_data_size)
        OSSL_ERR("Could not extract issuer and subject data.\n");

    databio = BIO_new(BIO_s_mem());
    if(!databio)
        OSSL_ERR("Could not create data BIO.\n");

    if(!BIO_write(databio, ias_data, ias_data_size))
        OSSL_ERR("Could not write issuer and subject data into BIO.\n");

    if((error = scep_p7_client_init(handle, req_pubkey, sig_cert, sig_key, &p7data)))
        goto finally;
    if((error = scep_pkiMessage(
            handle, messageType, databio, enc_cert, enc_alg, &p7data)) != SCEPE_OK)
        goto finally;
    if((error = scep_p7_final(handle, &p7data, pkiMessage)) != SCEPE_OK)
        goto finally;

finally:
    if(databio)
        BIO_free(databio);
    return error;
#undef OSSL_ERR
}

SCEP_ERROR scep_get_cert(
        SCEP *handle, X509_REQ *req, X509 *sig_cert, EVP_PKEY *sig_key,
        X509 *req_cert, X509 *enc_cert, const EVP_CIPHER *enc_alg,
        PKCS7 **pkiMessage)
{
    return _scep_get_cert_or_crl(
        handle, req, sig_cert, sig_key,
        req_cert, enc_cert, enc_alg,
        MESSAGE_TYPE_GETCERT, pkiMessage);
}

SCEP_ERROR scep_get_crl(
        SCEP *handle, X509_REQ *req, X509 *sig_cert, EVP_PKEY *sig_key,
        X509 *req_cert, X509 *enc_cert, const EVP_CIPHER *enc_alg,
        PKCS7 **pkiMessage)
{
    return _scep_get_cert_or_crl(
        handle, req, sig_cert, sig_key,
        req_cert, enc_cert, enc_alg,
        MESSAGE_TYPE_GETCRL, pkiMessage);
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















#include<unistd.h>


SCEP_ERROR scep_unwrap(
    SCEP *handle, PKCS7 *pkiMessage, X509 *cacert, EVP_PKEY *cakey, SCEP_DATA *output)
{
	SCEP_ERROR error = SCEPE_OK;
    /*should be in a separate init function*/
    int nid_messageType = OBJ_create("2.16.840.1.113733.1.9.2", "messageType",
        "messageType");
    if (nid_messageType == 0) {
        goto finally;
    }

    int nid_senderNonce = OBJ_create("2.16.840.1.113733.1.9.5", "senderNonce",
        "senderNonce");
    if (nid_senderNonce == 0) {
        goto finally;
    }

    int nid_transId = OBJ_create("2.16.840.1.113733.1.9.7", "transId",
        "transId");
    if (nid_transId == 0) {
        goto finally;
    }

    STACK_OF(PKCS7_SIGNER_INFO) *sk;
    PKCS7_SIGNER_INFO           *si;
    unsigned char				*buf;
    ASN1_TYPE                   *messageType, *senderNonce, *transId;
    char                        *issuer, *subject;
    X509                        *signerCert;
    STACK_OF(X509)              *certs;
    BIO                         *encData, *decData;
    X509_STORE                  *store;
#define OSSL_ERR(msg)                                   \
	do {                                                \
		error = SCEPE_OPENSSL;                          \
		ERR_print_errors(handle->configuration->log);   \
		scep_log(handle, FATAL, msg);                   \
		goto finally;                                   \
	} while(0)

    /*prepare trusted store*/
    store = X509_STORE_new();
    encData = NULL;
    decData = NULL;
    /*add trusted cert*/
    X509_STORE_add_cert(store, cacert);
    output->initialEnrollment = 0;
    /*extract signer certificate (only one?) from pkiMessage*/
    certs = PKCS7_get0_signers(pkiMessage, NULL, 0);
    signerCert = sk_X509_value(certs, 0);
    /*TODO: additional checks for generic attributes, version = 1 etc*/
	
    /* Message type*/
    if(!(sk = PKCS7_get_signer_info(pkiMessage)))
         OSSL_ERR("Failed to get signer info.\n");
    if(!(si = sk_PKCS7_SIGNER_INFO_value(sk, 0)))
         OSSL_ERR("Failed to get signer info value.\n");
    if(!(messageType = PKCS7_get_signed_attribute(si, nid_messageType)))
        OSSL_ERR("messageType is missing. Not a pkiMessage?.\n");
	
    /*luckily, standard defines unique types*/
    ASN1_STRING_to_UTF8(&buf,messageType->value.printablestring);
    output->messageType = (char*)buf;
    
    /*struct is redundant, however*/
    output->messageType_int = atoi(output->messageType);
    /*initial PKCSreq message could be selfsigned*/
    if(strcmp(output->messageType, MESSAGE_TYPE_PKCSREQ) == 0) {
        /*check for self-signed*/
        /*oneline avoids to check every single element*/
        issuer = X509_NAME_oneline(X509_get_issuer_name(signerCert), 0, 0);

        subject = X509_NAME_oneline(X509_get_subject_name(signerCert), 0, 0);
        if(*issuer == *subject)
            output->initialEnrollment = 1;
            X509_STORE_add_cert(store, signerCert);
    }
    
    if(verify(handle, pkiMessage, store, encData) != SCEPE_OK)
        goto finally;
	
    /*Message is a pkiMessage and consists of a valid signature. Lets see if we can decrypt it*/
    if(encData) {
        if(decrypt(handle, encData, cakey, cacert, decData) != SCEPE_OK)
             goto finally;
        if(strcmp(output->messageType, MESSAGE_TYPE_PKCSREQ) == 0) {
            output->request = NULL; 
            d2i_X509_REQ_bio(decData, &(output->request));
            /*TODO: fine, but request needs machting parameter to outer PKCSreq*/
        }
        /*TODO: each type needs own handling, depending to various parameters*/
    }
    else{
        /*TODO: no content to be encrypted, e.g. certrep failure, pending*/
    }
    
    /*pkiMessage attributes*/ 

    /*transaction id*/
    if(!(transId = PKCS7_get_signed_attribute(si, nid_transId)))
        OSSL_ERR("transaction ID is missiong.\n");
	
    ASN1_STRING_to_UTF8(&buf,transId->value.printablestring);
    output->transactionID = (char*)buf;
	
    /*senderNonce*/
    if(!(senderNonce = PKCS7_get_signed_attribute(si, nid_senderNonce)))
        OSSL_ERR("sender Nonce is missiong.\n");
     /*TODO: use ASN1_STRING_print_ex, write to bio, then from bio to hex string*/

    /*type-depending attributes*/  
    /*TODO*/

finally:
    return error;
#undef OSSL_ERR

}

SCEP_ERROR verify(
    SCEP *handle, PKCS7 *pkiMessage, X509_STORE * store, BIO *encData)
{
    //STACK_OF(X509) *certs;
    //X509 * cert;
    SCEP_ERROR error = SCEPE_OK;
#define OSSL_ERR(msg)                                   \
        do {                                                \
            error = SCEPE_OPENSSL;                          \
            ERR_print_errors(handle->configuration->log);   \
            scep_log(handle, FATAL, msg);                   \
            goto finally;                                   \
        } while(0)
    /*assuming cert is within pkiMessage*/
    if (!PKCS7_verify(pkiMessage, NULL, store, NULL, encData, 0)) {
        OSSL_ERR("verification failed");
    }
finally:
    return error;
#undef OSSL_ERR
}

SCEP_ERROR decrypt(
    SCEP *handle, BIO *encData, EVP_PKEY *cakey, X509 *cacert, BIO *decData)
{
    PKCS7 * p7enc;
    SCEP_ERROR error = SCEPE_OK;
#define OSSL_ERR(msg)                                   \
        do {                                                \
            error = SCEPE_OPENSSL;                          \
            ERR_print_errors(handle->configuration->log);   \
            scep_log(handle, FATAL, msg);                   \
            goto finally;                                   \
        } while(0)
    p7enc = d2i_PKCS7_bio(encData, NULL);
    if(!PKCS7_decrypt(p7enc, cakey, cacert, decData, 0)) {
        OSSL_ERR("decryption failed");
    }
finally:
    return error;
#undef OSSL_ERR
}
