=========================
Developer Design Document
=========================

This document outlines the design decisions made for ``libscep``. If you are a
user of this software, you are wrong here. However, if you want to contribute
to this project or want to understand the reasoning behind some decisions, then
you may find the information you are searching here.

Please note that this document is not created as a structured read. Thus,
contrary to the other sections of this documentation, the texts here
reflect the developemnt process. This is a practical decision: It eases
development and is not intended for a large audience anyway.

Layer I: The Concept
====================

The goal of ``libscep`` is to provide an implementation of the SCEP protocol.
Thus, the major concern lies with executing all operations of this protocol.
A user of this library intends to execute one or more operations in the process
of communication with a server. The goal of the library must therefore
primarily be the abstraction from the protocol to ease the execution of the
operations. As such, the library must be as simple and easy to use as possible
without putting too much burden upon the user of it.

Another important requirement is that of a first client: The traditional,
existing ``sscep`` client should be reimplemented to work with the library.
The client must not behave differently than the 'old' ``sscep`` as it is
used in production and a change would break those usages, preventing the users
from upgrading. On the other hand, the library **must not** orient its design
upon the existing client: The library needs a fresh design and the client then
must work around possible differences.

However, the library may provide functions to work around problems the client
has. This is done to provide these possibly useful functions to other clients
as well. If a lot of these functions are required, the design should be
re-evaluated to ensure that it is still valid and the requirement bases on a
flaw of the client.

Layer II: Using the Library
===========================

With the concept clear, the most important step is to specify how a user will
use the library. Here we will orient on a popular concept in C: Initiate the
library, use it and destroy it after it is not used any more.

Initialization
--------------

The process of initialization allocates all memory required and returns an
instance of the library to be used with a single server. We will call this
instance a *handle*.

Destruction
-----------

Closely related to the process of initialization is that of destruction. Here,
we will ensure that all memory gets properly deallocated before the handle is
freed. Afterwards, the handle is unusable and should not be used any more.

Using a Handle
--------------

After having created a handle, it can be used to execute operations. Before
these operations can be executed, it is required that the specific operations
are configured. For each operation there exists a different configuration so
it makes sense to make these configurations independent.

However, several common factors exist and these need to be identified. They are
configured globally for a handle and are valid across all operations. An example
of such a parameter is the *URL* of the SCEP server.

It must be decided how this process can be clearly split up into two:
Configuring the handle & configuring an operation. A possible option here is to
configure the handle right after it is created. Then, for an operation, it
should be configured right before it runs.


Layer III: Designing the Public API
===================================

The API is what makes the library valueable and thus it must be carefully
designed. Each function declared public must be well documented and
it should be taken care which functions are actually made available.

Mandatory public options are *initialization*, *desctruction*, *configuration*
and one function for each *operation*.


General Specification
---------------------

Each function that is in the public interface *must* return an error code if it
can have errors or return ``void`` if it does not handle any error.


Initialization
--------------

This is a very simple function that takes no parameters, creates the handle and
returns a pointer to it.

Desctruction
------------

This function takes a single handle and deallocates all memory for all
components in the handle.

Configuration
-------------

The configuration interface consists of a way to pass a single parameter for an
option. Additionally, a handle needs to be passed in on which the configuration
should be done. Also, the function accepts a region of configuration: Either for
an operation that is specified or globally.


The following configuration options are required (by opertaion/global):

* Global
    - URL of the SCEP server (with optional GET parameters).
    - A proxy server to be used. *Optional*.
    - Verbosity. *Optional*, has sane default.
    - Signature Algorithm. *Optional*, has sane default.
    - Encryption Algorithm. *Optional*, has sane default.
* GetCACert
    - Issuer of the certificate. *Optional*.
* PKCSReq (Enrollment)
    - Certificate Signing Request for private key.
    - Private Key for which to get the certificate.
    - CA certificate.
    - Challenge Password. *Optional*.
    - Signature Private Key with which to sign the PKCSReq message. *Optional*.
    - Signature Certificate corresponding to the Signature Private Key.
      *Optional* but mandatory, if Signature Private Key is set.
    - Polling interval. *Optional*, has sane default.
    - Maximum polling time. *Optional*, has sane default.
    - Maximum polling count. *Optional*, has sane default.
* GetCert
    - Private Key for which to get the certificate.
    - CA certificate for the issuer and serial number.
* GetCRL
    - Certificate to be validated.
* GetNextCACert
    - Issuer of the certificate. *Optional*.

The configuration also has a sanity check for each operation: This function
checks the given configuration on whether it makes sense before it tries to
execute.

Operations
----------

Each operation returns a value for the target of the operation, e.g. the
certificate retrieved. Since an actual return value must always be an error
code, this will be implemented as a parameter passed to the function as a
pointer.

Layer IV - The Internals
========================

With a public, consistent interface it is now possible to design the internals
after it. 
