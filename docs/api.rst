=================
API Documentation
=================

This document describes the API of ``libscep`` in detail. If you are looking 
for specific functions and implementation details you are correct here. If you
are looking for just using this library, the 
_`narrative documentation <narrative>` might be more for you.


Functions
=========

General functions
-----------------
.. function:: SCEP_ERROR scep_init(SCEP **handle)

    Initializes the :type:`SCEP` data structure and returns a success status.
    The memory for the contained structs is pre-allocated and can later be
    filled with some data, e.g. configuration values.

    Make sure to call :func:`scep_cleanup` when you are done.

.. function:: void scep_cleanup(SCEP* handle)

    Deallocate all memory that was reserved by the client during the process.
    Afterwards the data that was allocated is no longer accessible. Should be
    called at the end of the process, in conjuction with calling 
    :func:`scep_init` at the beginning.

    Note that there is some data that is not cleaned up. This is data which is
    documented to not be copied. Take a look at the specific configuration
    options you are using to avoid memory leaks.

.. function:: SCEP_ERROR scep_conf_set(SCEP* handle, SCEPCFG_TYPE type, ...)
   
   Set the option for ``handle`` of type ``type`` to the value passed as the
   last argument. The
   documentation for :type:`SCEPCFG_TYPE` describes which options are available
   and which parameters the function expects.

   All values passed to this function are copied (except if explicitly stated
   otherwise), so any memory allocated can 
   be freed after the option has been set. Freeing of the internal memory will 
   be done by :func:`scep_cleanup`.


Utility functions
-----------------

.. function:: char* scep_strerror(SCEP_ERROR err)

    Turns an internal error code into a human-readable string explaining the
    error code.

    Example usage:

    .. code-block:: c

        printf("Error message: %s\n", strerror(SCEPE_MEMORY));

Data Types
==========

This section lists the data types used within ``libscep``. 

.. type:: SCEP
    
    A handle to a single instance for ``libscep``. This needs to be passed to
    all functions that execute operations. It includes the configuration and
    some additional information.

.. type:: SCEP_ERROR

    An error code indicating a problem. Can be converted into human readable
    string using :func:`scep_strerror`. ``SCEPE_OK`` indicates that no error
    has happened and should be checked after calling any function that returns
    this type.

.. type:: SCEP_PKISTATUS

    Prefixed by ``SCEP_`` with possible suffixes ``SUCCESS``, ``PENDING``
    or ``FAILURE`` according to SCEP standard.

.. type:: SCEP_FAILINFO

    Enum that represents the ``failInfo`` field in a native way. All values are
    prefixed by ``SCEP_BAD_``. The suffix decides which type of error it is.
    Available suffixes: ``ALG``, ``MESSAGE_CHECK``, ``REQUEST``, ``TIME``,
    ``CERT_ID``, each corresponding to the failInfo field of an SCEP message.
    Only relevant if :type:`SCEP_PKISTATUS` is ``SCEP_FAILURE``.

.. type:: SCEP_MESSAGE_TYPE

    Enum that represents all possible messageType fields for SCEP. Prefixed
    by ``SCEP_MSG_`` and suffixed by one of ``PKCSREQ``, ``CERTREP``,
    ``GETCERTINITIAL``, ``GETCERT``, ``GETCRL``. The integers in the
    enum correspond to their defined value in the standard, e.g.
    ``SCEP_MSG_PKCSREQ`` has the value ``19``.

.. type:: SCEP_DATA

    Structure with all information contained in an SCEP pkiMessage in a more
    accessible way. Produced by :func:`scep_unwrap` and
    :func:`scep_unwrap_response`. The following field are defined:

    :param pkiStatus: The status of a CertRep message, irrelevant for others
    :type pkiStatus: SCEP_PKISTATUS
    :param failInfo: If ``pkiStatus`` is FAILURE, this contains additional
        information.
    :type failInfo: SCEP_FAILINFO
    :param transactionID: Transaction ID contained in request. This is
        always present. Stored hex encoded
    :type transactionID: char *
    :param senderNonce: Always present, exactly 16 byte long. Stored
        unencoded
    :type senderNonce: unsigned char *
    :param recipientNonce: Only present in CertRep, format like
        ``snederNonce``
    :type recipientNonce: unsigned char *
    :param challenge_passowrd: Challenge password extracted from a
        PKCSReq,  otherwise unset. Left at generic ``ASN1_TYPE`` to
        make no assumptions about its content, encoding, etc.
    :type challenge_password: ASN1_TYPE *
    :param signer_certificate: The certificate used to sign the message.
        Currently unused.
    :type signer_certificate: X509 *
    :param messageType_str: Representation of message type as a stringified
        integer, e.g. ``"19"`` for PKCSReq. Provided for convenience.
    :type messageType_str: char *
    :param messageType: Message type represented by an enum, can assume any
        valid SCEP messageType.
    :type messageType: SCEP_MESSAGE_TYPE
    :param request: Only set when messageType is PKCSReq, contains the
        CSR.
    :type request: X509_REQ *
    :param initialEnrollment: Only PKCSReq. Whether this is an initial
        enrollment message,
        determined by whether the request was self-signed. 1 if it is
        initial enrollment, 0 otherwise.
    :type initialEnrollment: int
    :param issuer_and_serial: Only GetCert and GetCRL.
    :type issuer_and_serial: PKCS7_ISSUER_AND_SERIAL
    :param issuer_and_subject: Only GetCertInitial.
    :type issuer_and_subject: PKCS7_ISSUER_AND_SUBJECT
    :param certs: Only CertRep if not response to GetCRL. Contains
        one or more certificate where the first one is the requested
        certificate (e.g. the newly issued in case of PKCSReq).
    :type certs: STACK_OF(X509) *
    :param crl: Only CertRep if response to GetCRL. Contains
        requested CRL.
    :type crl: X509_CRL *