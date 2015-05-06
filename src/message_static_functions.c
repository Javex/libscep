/*
 * This file is never to be compiled directly. Instead it should be included
 * by message.c.
 * It contains useful helper functions that make the main code more readable.
 */

static SCEP_ERROR make_degenP7(
    SCEP *handle, X509 *cert, STACK_OF(X509) *additionalCerts, X509_CRL *crl, PKCS7 **p7)
{
    SCEP_ERROR error = SCEPE_OK;
    PKCS7 *local_p7 = NULL;
    PKCS7_SIGNED *p7s = NULL;
    STACK_OF(X509) *cert_stack = NULL;
    STACK_OF(X509_CRL) *crl_stack = NULL;
    X509 *currCert = NULL;
    int i;

    /*input validation*/
    if(!((cert == NULL) ^ (crl == NULL)))
        SCEP_ERR(SCEPE_INVALID_PARAMETER, "cert and crl are mutually exclusive");

    /*quickly assemble degenerate pkcs7 signed-data structure*/
    if ((local_p7 = PKCS7_new()) == NULL)
        OSSL_ERR("could not create PKCS7 structure");
    if ((p7s = PKCS7_SIGNED_new()) == NULL)
        OSSL_ERR("could not create PKCS7 signed structure");
    local_p7->type = OBJ_nid2obj(NID_pkcs7_signed);
    local_p7->d.sign = p7s;
    /*TODO: not sure if this must be ommited, or if additionally empty content must be added*/
    p7s->contents->type = OBJ_nid2obj(NID_pkcs7_data);

    if (!ASN1_INTEGER_set(p7s->version, 1))
        OSSL_ERR("could not set version");

    if(cert) {
        if ((cert_stack = sk_X509_new_null()) == NULL)
            OSSL_ERR("could not create cert stack");

        p7s->cert = cert_stack;

        X509 *cert_copy = X509_dup(cert);
        if(!cert_copy)
            OSSL_ERR("Unable to copy certificate");
        if(!sk_X509_push(cert_stack, cert_copy))
            OSSL_ERR("Unable to add certificate to stack");

        if(additionalCerts) {
            scep_log(handle, DEBUG, "Adding %d additional certificate(s)", sk_X509_num(additionalCerts));
            for(i = 0; i < sk_X509_num(additionalCerts); i++) {
                currCert = sk_X509_value(additionalCerts, i);
                if(!currCert)
                    OSSL_ERR("No cert found in stack");
                cert_copy = X509_dup(currCert);
                if(!cert_copy)
                    OSSL_ERR("Unable to copy certificate");
                if(!sk_X509_push(cert_stack, cert_copy))
                    OSSL_ERR("Unable to extend cert stack");
            }
        }
    }
    else if(crl) {
        if ((crl_stack = sk_X509_CRL_new_null()) == NULL)
            OSSL_ERR("could not create crl stack");

        p7s->crl = crl_stack;
        sk_X509_CRL_push(crl_stack, crl);
    }

    *p7 = local_p7;

finally:
    return error;
}

/* Static helper methods for scep_unwrap
 * Reduces lines in scep_unwrap to keep things readable
 */

static SCEP_ERROR verify(
        SCEP *handle, PKCS7 *pkiMessage, X509 *ca_cert,
        BIO **encData)
{
    SCEP_ERROR error = SCEPE_OK;
    BIO *data = NULL;

    /* prepare trusted store */
    X509_STORE *store = X509_STORE_new();
    if(!store)
        OSSL_ERR("Unable to create cert store");

    /* add trusted cert */
    X509_STORE_add_cert(store, ca_cert);

    data = BIO_new(BIO_s_mem());
    if(!data)
        OSSL_ERR("Failed to create BIO for encrypted content");

    /* assuming cert is within pkiMessage */
    if (!PKCS7_verify(pkiMessage, NULL, store, NULL, data, 0))
        OSSL_ERR("verification failed");

    *encData = data;
finally:
    if(error != SCEPE_OK)
        if(data)
            BIO_free(data);
    if(store)
        X509_STORE_free(store);
    return error;
}

static SCEP_ERROR check_initial_enrollment(
        SCEP *handle, SCEP_DATA *data, X509 *signerCert)
{
    X509_NAME *subject, *issuer;
    SCEP_ERROR error = SCEPE_OK;
    data->initialEnrollment = 0;
    /* check for self-signed */
    issuer = X509_get_issuer_name(signerCert);
    if(!issuer)
        SCEP_ERR(SCEPE_INVALID_CONTENT, "Failed to extract issuer from certificate");
    subject = X509_get_subject_name(signerCert);
    if(!subject)
        SCEP_ERR(SCEPE_INVALID_CONTENT, "Failed to extract subject from certificate");

    if(X509_NAME_cmp(subject, issuer) == 0)
        data->initialEnrollment = 1;
finally:
    return error;
}

static SCEP_ERROR handle_certrep_attributes(
        SCEP *handle, SCEP_DATA *data, PKCS7_SIGNER_INFO *si)
{
    SCEP_ERROR error = SCEPE_OK;

    /* recipientNonce */
    ASN1_TYPE *recipientNonce = PKCS7_get_signed_attribute(si, handle->oids->recipientNonce);
    if(!recipientNonce)
        SCEP_ERR(SCEPE_INVALID_CONTENT, "recipientNonce is missing");
    ASN1_TYPE_get_octetstring(recipientNonce, data->recipientNonce, NONCE_LENGTH);

    /* pkiStatus */
    ASN1_TYPE *pkiStatus = PKCS7_get_signed_attribute(si, handle->oids->pkiStatus);
    if(!pkiStatus)
        SCEP_ERR(SCEPE_INVALID_CONTENT, "pkiStatus is missing");
    char *pki_status_str = (char *) ASN1_STRING_data(pkiStatus->value.printablestring);
    if(strncmp(pki_status_str, SCEP_PKISTATUS_SUCCESS, sizeof(SCEP_PKISTATUS_SUCCESS)) == 0)
        data->pkiStatus = SCEP_SUCCESS;
    else if(strncmp(pki_status_str, SCEP_PKISTATUS_FAILURE, sizeof(SCEP_PKISTATUS_FAILURE)) == 0)
        data->pkiStatus = SCEP_FAILURE;
    else if(strncmp(pki_status_str, SCEP_PKISTATUS_PENDING, sizeof(SCEP_PKISTATUS_PENDING)) == 0)
        data->pkiStatus = SCEP_PENDING;
    else {
        SCEP_ERR(SCEPE_PROTOCOL, "Invalid pkiStatus '%s'", pki_status_str);
    }

    /* failInfo */
    if(data->pkiStatus == SCEP_FAILURE) {
        ASN1_TYPE *failInfo = PKCS7_get_signed_attribute(si, handle->oids->failInfo);
        if(!failInfo)
            SCEP_ERR(SCEPE_INVALID_CONTENT, "failInfo is missing");
        char *failInfo_str = (char *) ASN1_STRING_data(failInfo->value.printablestring);
        if(strncmp(failInfo_str, SCEP_BAD_ALG_NR, sizeof(SCEP_BAD_ALG_NR)) == 0)
            data->failInfo = SCEP_BAD_ALG;
        else if(strncmp(failInfo_str, SCEP_BAD_MESSAGE_CHECK_NR, sizeof(SCEP_BAD_MESSAGE_CHECK_NR)) == 0)
            data->failInfo = SCEP_BAD_MESSAGE_CHECK;
        else if(strncmp(failInfo_str, SCEP_BAD_REQUEST_NR, sizeof(SCEP_BAD_REQUEST_NR)) == 0)
            data->failInfo = SCEP_BAD_REQUEST;
        else if(strncmp(failInfo_str, SCEP_BAD_TIME_NR, sizeof(SCEP_BAD_TIME_NR)) == 0)
            data->failInfo = SCEP_BAD_TIME;
        else if(strncmp(failInfo_str, SCEP_BAD_CERT_ID_NR, sizeof(SCEP_BAD_CERT_ID_NR)) == 0)
            data->failInfo = SCEP_BAD_CERT_ID;
        else {
            SCEP_ERR(SCEPE_PROTOCOL, "Invalid failInfo '%s'", failInfo_str);
        }
        scep_log(handle, INFO, "failInfo: %s", scep_fail_info_str(data->failInfo));
    }
finally:
    return error;
}

static SCEP_ERROR handle_encrypted_content(
        SCEP *handle, SCEP_DATA *data, PKCS7 *p7env, X509 *dec_cert,
        EVP_PKEY *dec_key)
{
    SCEP_ERROR error = SCEPE_OK;
    BIO *decData = NULL;
    int ias_data_size;
    unsigned char *ias_data = NULL;

    /* Sort out invalid Certrep PENDING or FAILURE requests */
    if(data->messageType == SCEP_MSG_CERTREP && data->pkiStatus != SCEP_SUCCESS)
        SCEP_ERR(SCEPE_INVALID_CONTENT, "PENDING or FAILURE Certreps MUST NOT have encrypted content");

    /* Outer type must be enveloped */
    if(!PKCS7_type_is_enveloped(p7env))
        SCEP_ERR(SCEPE_INVALID_CONTENT, "Encrypted data is not enveoloped type");

    /* Perform checks on the enveoloped content */
    if(ASN1_INTEGER_get(p7env->d.enveloped->version) != 0)
        SCEP_ERR(SCEPE_INVALID_CONTENT, "Version of the enveloped part MUST be 0");

    /* Check inner content type is pkcs7-data */
    if(OBJ_obj2nid(p7env->d.enveloped->enc_data->content_type) != NID_pkcs7_data)
        SCEP_ERR(SCEPE_INVALID_CONTENT, "content-type of pkcs7envelope MUST be pkcs7-data");

    decData = BIO_new(BIO_s_mem());
    if(!decData)
        OSSL_ERR("Failed to allocate space for decryption BIO");

    if(!PKCS7_decrypt(p7env, dec_key, dec_cert, decData, 0))
        OSSL_ERR("decryption failed");

    switch(data->messageType) {
        case SCEP_MSG_CERTREP:
            /* We set this as an intermediate value. messageData is only
             * an internal field and supposed to be parsed into the
             * correct field once scep_unwrap_response takes over.
             */
            data->messageData = d2i_PKCS7_bio(decData, NULL);
            if(!data->messageData)
                SCEP_ERR(SCEPE_INVALID_CONTENT, "Not valid PKCS#7 after decryption for CertRep");
            break;
        case SCEP_MSG_PKCSREQ:
            data->request = NULL;
            /* Message type PKCSreq means there MUST be a CSR in it */
            d2i_X509_REQ_bio(decData, &(data->request));
            if(!data->request)
                SCEP_ERR(SCEPE_INVALID_CONTENT, "Not valid CSR after decrpytion");

            /* Validate CSR against SCEP requirements */

            if(!(X509_REQ_get_subject_name(data->request)))
                SCEP_ERR(SCEPE_INVALID_CONTENT, "The CSR MUST contain a Subject Distinguished Name");

            EVP_PKEY *pub;
            if(!(pub = X509_REQ_get_pubkey(data->request)))
                SCEP_ERR(SCEPE_INVALID_CONTENT, "The CSR MUST contain a public key");
            EVP_PKEY_free(pub);

            int passwd_index = X509_REQ_get_attr_by_NID(data->request, NID_pkcs9_challengePassword, -1);
            if(passwd_index == -1)
                SCEP_ERR(SCEPE_INVALID_CONTENT, "The CSR MUST contain a challenge password");

            /* extract challenge password */
            X509_ATTRIBUTE *attr = X509_REQ_get_attr(data->request, passwd_index);
            if(attr->single == 0) { // set
                if(sk_ASN1_TYPE_num(attr->value.set) != 1)
                    SCEP_ERR(SCEPE_UNHANDLED, "Unexpected number of elements in challenge password");
                data->challenge_password = sk_ASN1_TYPE_value(attr->value.set, 0);
            } else { // single
                data->challenge_password = attr->value.single;
            }
            break;
        case SCEP_MSG_GETCERTINITIAL:
            ias_data_size = BIO_get_mem_data(decData, &ias_data);
            data->issuer_and_subject = d2i_PKCS7_ISSUER_AND_SUBJECT(NULL, (const unsigned char **) &ias_data, ias_data_size);
            if(!data->issuer_and_subject)
                SCEP_ERR(SCEPE_INVALID_CONTENT, "Unreadable Issuer and Subject data in encrypted content");
            break;
        case SCEP_MSG_GETCRL:
        case SCEP_MSG_GETCERT:
            ias_data_size = BIO_get_mem_data(decData, &ias_data);
            data->issuer_and_serial = d2i_PKCS7_ISSUER_AND_SERIAL(NULL, (const unsigned char **) &ias_data, ias_data_size);
            if(!data->issuer_and_serial)
                SCEP_ERR(SCEPE_INVALID_CONTENT, "Unreadable Issuer and Serial data in encrypted content");
            break;
    }

finally:
    if(decData)
        BIO_free(decData);
    return error;
}