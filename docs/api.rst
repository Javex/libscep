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
.. function:: SCEP* scep_init()

    Initializes the :type:`SCEP` data structure and returns a pointer to it.
    The memory for the contained structs is pre-allocated and can later be
    filled with some data, e.g. configuration values.

    Make sure to call :func:`scep_cleanup` when you are done.

.. function:: void* scep_cleanup(SCEP* handle)

    Deallocate all memory that was reserved by the client during the process.
    Afterwards the data that was allocated is no longer accessible. Should be
    called at the end of the process, in conjuction with calling 
    :func:`scep_init` at the beginning.

.. function:: void scep_set_conf(SCEP* handle, SCEPCFG_TYPE type, void* cfg_value)
   
   Set the option for ``handle`` of type ``type`` to value ``cfg_value``. The
   documentation for :type:`SCEPCFG_TYPE` describes which options are available
   and which parameters the function expects.

   All values passed to this function are copieds, so any memory allocated can 
   be freed after the option has been set. Freeing of the internal memory will 
   be done by :func:`scep_cleanup`.


Utility functions
-----------------

.. function:: SCEP_URL* scep_urlparse(char* url)

    Parse a string into an :type:`SCEP_URL` struct. The returned struct needs
    to be deallocated after it has been used. If passing this in as an option,
    it can be cleared after the option is set, as ``libscep`` makes a copy of
    it.

.. function:: StrMap* scep_queryparse(char* query)

    Parse a string into a :type:`StrMap`. The string should be a typical GET
    query, e.g. ``key1=value1&key2=value2``. Do not start the string with a
    ``?``. The memory needs to be deallocated by the caller. See
    :func:`scep_urlparse` for details.

Internal functions
------------------

These functions are only here as a reference documentation. They should never
be used from the outside.

.. function:: void scep_set_conf_url(SCEP* handle, SCEPCFG_TYPE type, SCEP_URL* url)

    Accepts a URL and sets either the ``url`` or ``proxy`` of the ``handle``'s
    configuration, depending on ``type``. Makes a copy of all the data in 
    ``url``. Counterpart :func:`scep_cleanup_conf_url` used to free memory
    allocated here.

.. function:: void scep_set_conf_encalg(SCEP* handle, SCEP_ENCRYPTION_ALG encalg)

    Set encryption algorithm.

.. function:: void scep_set_conf_sigalg(SCEP* handle, SCEP_SIGNATURE_ALG sigalg)

    Set signature algorithm.

.. function:: void scep_set_conf_verbosity(SCEP* handle, SCEP_VERBOSITY verbosity)

    Set verbosity level.

.. function:: void scep_cleanup_conf(SCEP_CONFIGURATION* conf)

    Cleans all resources that were allocated for the configuration.

.. function:: void scep_cleanup_conf_url(SCEP_URL* url)

    Frees all memory used by the ``url`` if it was allocated.

Data Types
==========

This section lists the data types used within ``libscep``. 

.. type:: SCEP
    
    A handle to a single instance for ``libscep``. This needs to be passed to
    all functions that execute operations. It includes the configuration and
    some additional information.

.. type:: SCEP_CONFIGURATION

    :type:`SCEP_URL` url: The URL to the SCEP server.

    :type:`SCEP_URL` proxy: An additional proxy server. Optional.

    :type:`SCEP_ENCRYPTION_ALG` encalg: The encryption algorithm to use.
    For possible options see :type:`SCEP_ENCRYPTION_ALG`.

    :type:`SCEP_SIGNATURE_ALG` sigalg: The signature algorithm to use.
    For possible options see :type:`SCEP_SIGNATURE_ALG`.

    :type:`SCEP_VERBOSITY` verbosity: How much information ``libscep`` should
    put out.

    :type:`StrMap*` additional_query: An optional query that should be sent to 
    the server. Add and retrieve values with [...]

    .. todo::

    Add functions for adding and retrieveing parameters in ``additional_query``.

.. type:: SCEP_URL

    :type:`SCEP_SCHEME` scheme: The protocol that should be used (either 
    ``HTTP`` or ``HTTPS``.

    :type:`char*` hostname: The hostname of the URL (e.g. ``google.com``.

    :type:`int` port: The port to use. For ``HTTP`` most likely ``80`` and for
    ``HTTPS`` most likely ``443``. If left empty, a sane default is chosen when
    using the appropriate functions.

    :type:`char*` path: The absolute path on where to contact the scep server.
    For example, ``/cgi-bin/scep/scep``.

.. type:: SCEPCFG_TYPE
    
    An ``enum``. Represents the different possible options. For each 
    configuration option it is described what the third parameter must be.
    This is then set in the configuration.

    Available options:

        ``SCEPCFG_URL``: Configure the SCEP server URL. Pass an 
        :type:`SCEP_URL`. Use :func:`scep_urlparse` to turn a string into a 
        struct you can pass to this function.

        ``SCEPCFG_PROXY``: Same as ``SCEPCFG_URL`` but for a proxy.

        ``SCEPCFG_ENCALG``: Pass one of the available options of 
        :type:`SCEP_ENCRYPTION_ALG`.

        ``SCEPCFG_SIGALG``: Pass one of the available options of
        :type:`SCEP_SIGNATURE_ALG`.

        ``SCEPCFG_VERBOSE``: Pass either ``true`` or ``false``. Sets verbose
        output.

        ``SCEPCFG_DEBUG``: Pass either ``true`` or ``false``. Sets debug
        output. Includes verbose output.

        ``SCEPCFG_ADDQUERY``: Configure additional data that should be sent to
        the server via a GET request. Pass in a data structure of type
        :type:`StrMap`. You can create this data structure with the help of 
        :func:`scep_queryparse`.

.. type:: SCEP_SIGNATURE_ALG

    An ``enum``. Describes which signature algorithm to use. Currently ``MD5``
    and ``SHA1`` are avaiable.
    
.. type:: SCEP_ENCRYPTION_ALG
    
    An ``enum``. Describes which encryption algorithm to use. Currently ``DES``, 
    ``TRIPLE_DES`` and ``BLOWFISH`` are available.

.. type:: SCEP_SCHEME

    An ``enum``. Choose the scheme, either ``HTTP`` or ``HTTPS``.

.. type:: SCEP_VERBOSITY

    An ``enum``. How much ``libscep`` "talks". The following levels are 
    avaiable, ordered by level of output (higher == less output). Also every
    element in the list includes the output from all above.

    * ``FATAL``: Only give output on critical errors that prevent ``libscep``
        from continuing.
    * ``ERROR``: Only give output when an unexpected condition happens that
        can not be corrected.
    * ``WARN``: Give output if something happens that should be looked into.
        Output on this level must not necessarily mean there is a problem, as
        long as it is looked into and confirmed working.
    * ``INFO``: Talk a lot. ``libscep`` gives detailed status information on
        what it is currently doing. Useful to create extensive logging but can
        generate a lot of output
    * ``DEBUG``: ``libscep`` gives very detailed information, including 
        printing certificates and other internal structures. Mostly useful for
        developers and generally only activated upon developer request.

.. type:: StrMap
    
    A local hash table implementation take from 
    `here <http://pokristensson.com/strmap.html>`_.
