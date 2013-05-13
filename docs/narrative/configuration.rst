=============
Configuration
=============

This page documents the available options for the library. Some of the options
explained below explicitly state that you are responsible for freeing the
memory corresponding to that options. The reason is twofold: First, it
is not possible to generically do a deep copy of an object and second, because
of potential performance implications.

So while the client copies *almost* all options, some, mostly OpenSSL structs,
are not. Pay attention to this when using the library.

.. todo::

    There is currently not very precisely defined behaviour in the code: Does
    it free? Does it copy? How and when doesn't it? It would possibly be a
    good approach to just never free any OpenSSL type and make it clear that
    the freeing has to be done by the user on all OpenSSL types. Then we could
    relentlessly overwrite all options. Currently, it seems we just free the
    old one and assign the new one (which is confusion to everyone).

Configuration is done via :func:`scep_conf_set`. The options described here
are passed as the ``type`` parameter.

Options that marked as mandatory but belong to a specific operation are only
mandatory for this operation (and ignored otherwise).

General Configuration
=====================

The options described here are valid for all operations unless stated
otherwise. They configure the general behaviour of the library, for
example logging and the Server's URL.

``SCEPCFG_URL``: Configures the absolute, full SCEP server URL as a ``char *``,
e.g. ``http://example.com/cgi-bin/scep/scep``. *Mandatory*.

``SCEPCFG_PROXY``: A proxy to go through, ``char *``. *Optional*.

.. todo::

    Implement

``SCEPCFG_VERBOSITY``: Configure the logging verbosity. Only makes sense in
conjuction with ``SCEPCFG_LOG``. *Optional*. Takes one of the following values:

* FATAL
* ERROR
* WARN
* INFO
* DEBUG

Defaults to ERROR.

``SCEPCFG_LOG``: A logging object, specifically an OpenSSL ``BIO*`` object. The
reason for this is, that it allows full flexibility and does not limit you to
a file pointer or string. Example:

.. code-block:: c

	scep_log = BIO_new_fp(stdout, BIO_NOCLOSE);
	scep_conf_set(handle, SCEPCFG_LOG, scep_log);

*Optional*.

``SCEPCFG_SIGALG``: The signature algorithm to use, an OpenSSL ``EVP_MD*``
object. Defaults to ``EVP_md5()``.

``SCEPCFG_ENCALG``: The encryption algorithm to use, an OpenSSL
``EVP_CIPHER*`` object. Defaults to ``EVP_des_cbc()``.

GetCACert Configuration
=======================

Only used with the GetCACert operation.

``SCEPCFG_GETCACERT_ISSUER``: The certificate issuer that is requested.
*Optional*.

PKCSReq Configuration
=====================

Only used with the PKCSReq operation.

``SCEPCFG_PKCSREQ_CSR``: The CSR for which the certificate is requested, an 
``X509_REQ*`` type.

``SCEPCFG_PKCSREQ_KEY``:

``SCEPCFG_PKCSREQ_CACERT``:

``SCEPCFG_PKCSREQ_CHALL_PASSWD``:

``SCEPCFG_PKCSREQ_SIGKEY``:

``SCEPCFG_PKCSREQ_SIGCERT``:

``SCEPCFG_PKCSREQ_POLL_INTERVAL``:

``SCEPCFG_PKCSREQ_POLL_TIME``:

``SCEPCFG_PKCSREQ_POLL_COUNT``:

GetCert Configuration
=====================

Only used with the GetCert operation.

``SCEPCFG_GETCERT_KEY``:

``SCEPCFG_GETCERT_CACERT``:


GetCRL Configuration
====================

Only used with the GetCRL operation.

``SCEPCFG_GETCRL_CERT``:

GetNextCACert Configuration
===========================

Only used with the GetNextCACert operation.

``SCEPCFG_GETNEXTCACERT_ISSUER``:
