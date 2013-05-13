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


Operation Functions
-------------------

.. function:: SCEP_ERROR scep_operation_getcacert(SCEP *handle, STACK_OF(X509) **certs);
    
    Execute the GetCACert operation of the SCEP protocol. The second parameter
    is a pointer to a ``STACK_OF(X509)`` collection of certs. This is where the
    resulting certificates will be stored.

    .. note::
        Currently only CA/RA Certificate Response is implemented (not CA only).

.. function:: SCEP_ERROR scep_operation_pkcsreq(SCEP *handle, X509 **cert);

    Execute the PKCSReq operation (enrollment). The ``**cert`` variable will
    hold the resulting certificate.

    .. todo::

        Implement

.. function:: SCEP_ERROR scep_operation_getcert(SCEP *handle, X509 **cert);

    Execute the GetCert operation. The ``cert`` variable will contain the
    requested certificate upon success.

    .. todo::

        Implement

.. function:: SCEP_ERROR scep_operation_getcrl(SCEP *handle, X509_CRL **crl);
    
    Execute the GetCRL operation. The ``crl`` variable will contain the
    requested CRL upon success.

    .. todo::

        Implement

.. function:: SCEP_ERROR scep_operation_getnextcacert(SCEP *handle, X509 **cert);

    Execute the GetNextCACert operation. The ``cert`` variable will contain the
    new CA certificate upon success.

    .. todo::

        Implement

Data Types
==========

This section lists the data types used within ``libscep``. 

.. type:: SCEP
    
    A handle to a single instance for ``libscep``. This needs to be passed to
    all functions that execute operations. It includes the configuration and
    some additional information.
