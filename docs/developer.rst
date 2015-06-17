***********************
Developer Documentation
***********************

Running Tests
=============

To run tests, it is required to have a proper setup or the engine tests will not work. First of all, the following requirements need to be installed:

* `libbotan <https://botan.randombit.net/>`_
* `SoftHSM <https://www.opendnssec.org/softhsm/>`_
* `libp11 <https://github.com/OpenSC/libp11>`_
* `engine_pkcs11 <https://www.opensc-project.org/opensc/wiki/engine_pkcs11>`_

If everything has been installed, you need to set the correct environment variables:

* ``MODULE_PATH`` must point to ``libsofthsm.so``, e.g. in ``/usr/lib/``
* ``ENGINE_PATH`` must point to ``engine_pkcs11.so``, e.g. in ``/usr/lib/engines``
* *Optionally*, ``LD_LIBRARY_PATH`` must include the directory where ``libbotan`` is found, which is only required if it is installed in a non-standard location

Before you can now run tests, you need a keyfile:

.. code-block:: text

    echo "0:softhsm-slot0.db" > softhsm.conf
    openssl genrsa -out some_key.pem
    openssl pkcs8 -topk8 -in some_key.pem -out some_key.p8 -nocrypt
    softhsm --init-token --slot 0 --label "foo" --pin 1234 --so-pin 123456
    softhsm --import some_key.p8 --slot 0 --pin 1234 --label foo --id 01
    rm some_key.pem some_key.p8

Then we can run our tests:

.. code-block:: text

    mkdir build
    cd build
    cmake ..
    make build_test
    ctest --output-on-failure
