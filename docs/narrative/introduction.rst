============
Introduction
============

Before you start using this library, we need to go over a few basic concepts
for generally using ``libscep``.

.. _params:

Paramters & Return Values
=========================

All ``libscep`` functions return an error status of type :type:`SCEP_ERROR`.
You must always check that this value is ``SCEPE_OK``. If it is not, you must
not use the return parameters in any way and instead handle the error return
by the function and potentially fail gracefully. A typical example would look
like this:

.. code-block:: c

    SCEP *handle;
    SCEP_ERROR error = scep_init(&handle);
    if(error != SCEPE_OK)
        /* handle error */

    /* continue normally */

Output parameters are always passed in last. The above example already shows a
good example of that though it has no input parameters. Each function
documents on how these paramters are used generally they are only every set in
case of success and not touched beforehand.

Concept of SCEP
===============

The basic library offers functionality to build and decompose SCEP both for
client and server. However, the protocol defines some properties that lie beyond
building the messages such as the transport to be used. This is not an integral
part of the library itself and is left to the individual implementations on how
this is achieved. The bindings in Perl, Python or calls from the command line
might have different requirements and the library does not force any kind of
behavior on the user here.

Public API
==========

.. _common_params:

Common Parameters
-----------------

Many of the functions share similar parameters which we wish to document here instead of separately on each function. The variable names in the signature are the same for all concerned functions.

.. function:: SCEP_ERROR scep_message_function()

    :param handle: SCEP handle, see ?? (init...)
    :type handle: SCEP *
    :param sig_cert: Sign PKCS#7 request with this. This will often be the
        old certificate with which to sign the request for renewal. It is
        also allowed to use a self-signed certificate here (see ??, 
        selfsigned stuff)
    :type sig_cert: X509 *
    :param sig_key: Key corresponding to ``sig_cert``.
    :type sig_key: EVP_PKEY *
    :param enc_cert: Certificate with which to encrypt the request. Usually
        this is the CA/RA certificate for the SCEP server.
    :type enc_cert: X509 *
    :param pkiMessage: This is an out-parameter: It will be set to a pointer
        of a PKCS#7 message if the function completes successfully. Otherwise
        it will be left in its previous state.
    :type pkiMessage: PKCS7 **
    :return: Error status, see :ref:`params`.
    :rtype: SCEP_ERROR

PKCSReq
-------

.. function:: SCEP_ERROR scep_pkcsreq(SCEP *handle, X509_REQ *req, X509 *sig_cert, EVP_PKEY *sig_key, X509 *enc_cert, PKCS7 **pkiMessage)

    Create a PKCSReq pkiMessage. See :ref:`common_params`. Special
    parameters:

    :param req: Request for which the PKCSReq message should be created.
    :type req: X509_REQ *

CertRep
-------

.. function:: SCEP_ERROR scep_certrep(SCEP *handle, char *transactionID, char *senderNonce, char *pkiStatus, SCEP_FAILINFO failInfo, X509 *requestedCert, X509 *sig_cert, EVP_PKEY *sig_key, X509 *enc_cert, STACK_OF(X509) *additionalCerts, X509_CRL *crl, PKCS7 **pkiMessage)

    :param transactionID: Transaction ID chosen by the client, needs to be 
        copied over so must stay the same as in the request.
    :type transactionID: char *
    :param senderNonce: Nonce used by sender in original request.
    :type senderNonce: char *
    :param pkiStatus: One of ``FAILURE``, ``SUCCESS`` or ``PENDING``.
    :type pkiStatus: char *
    :param failInfo: Only makes sense if ``pkiStatus`` is ``FAILURE``.
        In that case should represent the correct error according to the
        standard.
    :type failInfo: SCEP_FAILINFO
    :param requestedCert: Certificate that was requested. Which certificate
        that is depends on the request, e.g. may be newly issued cert in case
        of a PKCSReq.
    :type requestedCert: X509 *
    :param additionalCerts: If you want to add more certificates, to your
        response, you can use this parameter to add them to the response.
        The client may ignore them.
    :type additionalCerts: STACK_OF(X509) *
    :param crl: If a CRL was requested instead of a certificate, set this
        parameter.
    :type crl: X509_CRL *

GetCertInitial
--------------

.. function:: SCEP_ERROR scep_get_cert_initial(SCEP *handle, X509_REQ *req, X509 *sig_cert, EVP_PKEY *sig_key, X509 *cacert, X509 *enc_cert, PKCS7 **pkiMessage)

    :param req: The request for which this message should be created. It
        basically needs the subject defined here to create the appropriate
        request to the server.
    :type req: X509_REQ *
    :param cacert: Certificate of the CA from which the request expects a new
        certificate to be issued. This may be the same as ``enc_cert`` but
        can also be different, depending on the PKI setup.
    :type cacert: X509 *

GetCert
-------

.. function:: SCEP_ERROR scep_get_cert(SCEP *handle, X509 *sig_cert, EVP_PKEY *sig_key, X509_NAME *issuer, ASN1_INTEGER *serial, X509 *enc_cert, PKCS7 **pkiMessage)

    :param issuer: Name of the certificate issuer.
    :type issuer: X509_NAME *
    :param serial: Serial number of requested certificate.
    :type serial: ASN1_INTEGER *

GetCRL
------

.. function:: SCEP_ERROR scep_get_crl(SCEP *handle, X509 *sig_cert, EVP_PKEY *sig_key, X509 *req_cert, X509 *enc_cert)

    :param req_cert: Certificate for which CRL should be requested
    :type req_cert: X509 *

Unwrapping
----------

Unwrapping of requests is done directly with :func:`scep_unwrap`, responses
should be parsed with the wrapper :func:`scep_unwrap_response` as this
translates the degenerate  PKCS#7 returned by CertRep into their corresponding
type, i.e. certificate or CRL.

.. function:: SCEP_ERROR scep_unwrap(SCEP *handle, PKCS7 *pkiMessage, X509 *ca_cert, X509 *dec_cert, EVP_PKEY *dec_key, SCEP_DATA **output)

    :param pkiMessage: Contrary to the creation cases, this unpacks a
        PKCS#7 message and so this is an input parameter (the message)
        received from the client.
    :type pkiMessage: PKCS7 *
    :param ca_cert: Root CA certificate used for signature verifcation.
    :type ca_cert: X509 *
    :param dec_cert: Decryption certificate (either SCEP server or
        requester certificate).
    :type dec_cert: X509 *
    :param dec_key: Private key corresponding to ``dec_cert``.
    :type dec_key: EVP_PKEY *
    :param output: Data structure in which all information obtained
        from parsing should be put. See :type:`SCEP_DATA` for
        information on which fields have which meaning.
    :type output: SCEP_DATA **

.. function:: SCEP_ERROR scep_unwrap_response(SCEP *handle, PKCS7 *pkiMessage, X509 *ca_cert, X509 *request_cert, EVP_PKEY *request_key, SCEP_OPERATION request_type, SCEP_DATA **output)

    This is basically the same as :func:`scep_unwrap` but handles extracting
    the correct type of response from the degenerate PKCS#7. Thus, parameters
    are mostly the same as with :func:`scep_unwrap`. Exception:

    :param request_type: This indicates the type of request that was made
        for which this message is a response. This is necessary to interpret
        the encrypted content.
    :type request_type: SCEP_OPERATION