***********************
Developer Documentation
***********************

Running Tests
=============

Running tests is designed to be as easy as possible. However, due to our engine support and the corresponding tests, various dependencies are introduced. Now, the easiest way to get things running is not to care at all. Just go ahead and run this:

.. code-block:: text

    mkdir build
    cd build
    cmake ..
    make build_test
    ctest --output-on-failure

This should create everything as it is needed without no need for intervention. However, this is by far not the quickest way because a lot of libraries have to be built (and if you delete the build directory, they will be built again).

Manually Installing Dependencies
--------------------------------

If you want to have quicker builds, you can manually install the dependencies, possibly from your package manager. Here is a list of all the required packages:

* `libbotan <https://botan.randombit.net/>`_
* `SoftHSM <https://www.opendnssec.org/softhsm/>`_
* `libp11 <https://github.com/OpenSC/libp11>`_
* `engine_pkcs11 <https://www.opensc-project.org/opensc/wiki/engine_pkcs11>`_

If you installed everything and their are fairly sane locations, running the code from the previous section should find these. If not, it will probably just build them anyway. It should also find all the correct paths to modules and libraries it requires or will complain if it doesn't. If you have suggestions on how to improve this process, please let us know.