*******
Engines
*******

libscep has support for `OpenSSL engines`_. Because the core functionality is completely independent from any engine support due to the generic PKEY interface, we only provide convenience functions and documentation.

.. _OpenSSL engines: https://www.openssl.org/docs/crypto/engine.html

OpenSSL offers a high flexibility for using engines, but in 90% of the cases the operations you perform are the same. Thus, the functions offered by libscep take this burden from you in these cases. In the remaining 10% you can use OpenSSL's original support without loss of flexbility or functionality.

Configuration
=============

There are two types of engines with OpenSSL. First, builtin engines exist that OpenSSL already knows about. Second, an engine called ``dynamic`` is able to load engines not already part of OpenSSL during runtime. To ease usage, both ways are supported through a very similar interface.

To load a builtin engine you configure libscep like this:

.. code-block:: c

    scep_conf_set(handle, SCEPCFG_ENGINE, "chil");

This will load the builtin ``chil`` engine. On the other hand, a much more common use-case would be to load the engine dynamically:

.. code-block:: c

    scep_conf_set(handle, SCEPCFG_ENGINE, "dynamic", "pkcs11", "/path/to/engine_pkcs11.so");

This will do several things, but the basic gist is this: If you pass ``dynamic`` as the first configuration parameter, two more will be expected: The first denoting the engine ID (while this is your choice, it is generally clear how it should be named). The second parameter then is the path to the acutal shared object.

In both cases after calling this the engine will be fully operational if no error has been reported. However, some engines might require additional variables to be set up to work. In our example above, the `PKCS#11 engine`_ requires a ``MODULE_PATH`` variable to be set. Thus, it is possible to set any number of variables before loading the engine:

.. _PKCS#11 engine: https://www.opensc-project.org/opensc/wiki/engine_pkcs11

.. code-block:: c

    scep_conf_set(handle, SCEPCFG_ENGINE_PARAM, "MODULE_PATH", "/path/to/module.so");

Before the engine is actually loaded, the ``MODULE_PATH`` variable is set accordingly. To get a list of possible parameters see :ref:`trick_param_list`.

.. note::

    Because these parameters have to be set before the engine is loaded it is not allowed to set parameters after an engine has been loaded (this would be useless anyways).


More Flexibility
----------------

If you require more flexibility, you can create your own engine object to your liking and then just hand it to the library:

.. code-block:: c

    scep_conf_set(handle, SCEPCFG_ENGINE_OBJ, engine);

In this case, libscep will only keep a reference to it but not take ownership of it: You are responsible for cleaning it up.

.. warning::

    If you create multiple handles and mix ``SCEPCFG_ENGINE_OBJ`` and ``SCEPCFG_ENGINE`` you have to take care of the cleanup order: The global cleanup function ``ENGINE_cleanup`` is called if the last engine libscep knows about is freed. But this only applies if this engine was not passed in through ``SCEPCFG_ENGINE_OBJ``. So: Always cleanup in the reverse order you set up and if your explicit engine is the last, you must call ``ENGINE_cleanup`` yourself, otherwise you **must not**.


Using the Engine
================

Because of the massive flexibility of the engine API and the diverse usage, we currently do not offer a wrapper around OpenSSL's engine functions. In the most general case, you want to load a private key from your engine:

.. code-block:: c

    ENGINE *engine = NULL;
    scep_engine_get(handle, &engine);
    EVP_PKEY *key = ENGINE_load_private_key(engine, "0:01", NULL, NULL);

``scep_engine_get`` gives you a reference to the configured engine. Even if you configured the engine explicitly with ``SCEPCFG_ENGINE_OBJ`` you **must** use this interface for the engine. Afterwards, you can freely use the obtained reference on any OpenSSL engine functions.

In the example above, a private key is loaded from our previously configured PKCS#11 engine, loading key with ID ``0x01`` from slot ``0``. We do not provide the optional callback and data parameters.

That's basically it: You now have an ``EVP_PKEY`` object usable with the library as OpenSSL is completely transparent regarding these anyway. For engine-specific actions and some additional details, refer to the next section.

Special Engines
===============

Unfortunately, it often is not that simple because even though there exists a generic interface, technical differences exist. Thus, special handling is required for most engines. Since libscep does not know about these specialties, it is up to the programmer to take control. This is the main reason why we hand out an engine object instead of offering wrapping functions.

To aid you with this process, we provide documentation for several engines. If you have any suggestions, improvements or similar, please let us know and we will add it here.

pkcs11_engine
-------------

With PKCS#11 you are often required to enter a PIN. The engine offers various methods to provide this PIN but the most simple is globally setting it:

.. code-block:: c

    ENGINE_ctrl_cmd_string(engine, "PIN", "1234", 0);


capi
----

The capi engine for Microsoft's CryptoAPI can also be used, but might sometimes need extra parameters.

First of all, a store name has to be given. The default name for it is ``MY`` but when a new key with CSR is created, it is stored in the ``REQUEST`` store:

.. code-block:: c

    ENGINE_ctrl_cmd_string(engine, "store_name", "REQUEST", 0);

Also, if the system store instead of the user's store should be used:

.. code-block:: c

    ENGINE_ctrl_cmd(engine, "store_flags", 1, NULL, NULL, 0);

  
Tricks
======

Here are a few tricks that might help you in one case or another.

.. _trick_param_list:

Getting a List of Supported Parameters for ``SCEPCFG_ENGINE_PARAM``
-------------------------------------------------------------------

Whenever you call ``scep_conf_set`` with ``SCEPCFG_ENGINE_PARAM``, under the hood, ``ENGINE_ctrl_cmd_string`` is called. Thus, any parameter supported by an engine can be set here. For builtin engines, getting a list of these is fairly easy. For example, for CHIL:

.. code-block:: text

    $ openssl engine chil -vvv
    (chil) CHIL hardware engine support
     SO_PATH: Specifies the path to the 'hwcrhk' shared library
          (input flags): STRING
     FORK_CHECK: Turns fork() checking on (non-zero) or off (zero)
          (input flags): NUMERIC
     THREAD_LOCKING: Turns thread-safe locking on (zero) or off (non-zero)
          (input flags): NUMERIC


Getting this for dynamically loaded engines is a bit more complicated:

.. code-block:: text

    openssl engine dynamic -pre SO_PATH:path/to/engine_pkcs11.so -pre ID:pkcs11 -pre LIST_ADD:1 -pre LOAD -vvv
    (dynamic) Dynamic engine loading support
    [Success]: SO_PATH:/home/javex/tmp/lib/engines/engine_pkcs11.so
    [Success]: ID:pkcs11
    [Success]: LIST_ADD:1
    [Success]: LOAD
    Loaded: (pkcs11) pkcs11 engine
         SO_PATH: Specifies the path to the 'pkcs11-engine' shared library
              (input flags): STRING
         MODULE_PATH: Specifies the path to the pkcs11 module shared library
              (input flags): STRING
         PIN: Specifies the pin code
              (input flags): STRING
         VERBOSE: Print additional details
              (input flags): NO_INPUT
         QUIET: Remove additional details
              (input flags): NO_INPUT
         INIT_ARGS: Specifies additional initialization arguments to the pkcs11 module
              (input flags): STRING

.. note::

    Currently, we only support string values here. ``NO_INPUT`` might also work if you pass ``NULL`` as a value but this is untested.
