=================
The SCEP Protocol
=================

Here, the SCEP protocol is described *as needed by the client*. This document
should not considered a reference for the protocol nor does it guarantee
completeness or correctness. It is only intended as a help for the
development documentation.

Operation Overview
==================

A brief overview over the available operations and their requirement /
behaviour.

GetCACert
---------

Request: Only has a GET string ``operation=GetCACert``. No data associated.

PKCSReq (Enrollment)
--------------------

A PKCSReq message.

GetCertInitial
--------------

Send this message in a polling mode: Repeatedly, until time limit or polling
count is exceeded. Sends ``transactionID`` and ``SubjectName`` to identify
requested certificate.

GetCert
-------

``messageData`` consists of ``IssuerAndSerial``, ``authenticatedAttributes``
includes ``transactionID``, ``messageType`` and ``senderNonce``.

GetCRL
------

Either use *CRL Distribution Point* or ``GetCRL`` message.

GetNextCACert
-------------

Only has a GET string ``operation=GetNextCACert``. No data associated.
