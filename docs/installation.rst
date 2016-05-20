************
Installation
************

Installation Methods
====================

To add Dispersy to your program you can use one of the following methods:

Git Submodule
-------------

You can add Dispersy to your program by adding it as a submodule of your git repository

.. code-block:: python

   git submodule add git@github.com:Tribler/dispersy.git dispersy

then you can start building your communities.

Installing Dependencies
=======================

* python 2.7 (Dispersy runs only on python 2.7 because of twisted)
* twisted
* netifaces
* M2Crypto
* Libsodium
* PyCrypto

Linux
-----

Apt-get
^^^^^^^
.. code-block:: python

   sudo apt-get install python-twisted
   sudo apt-get install python-netifaces
   sudo apt-get install python-m2crypto
   sudo apt-get install libsodium-dev
   pip install pycrypto

if your system is not Debian >= 8 or Ubuntu >= 15.04 use:

.. code-block:: python

   sudo add-apt-repository ppa:chris-lea/libsodium
   sudo apt-get update && sudo apt-get install libsodium-dev

Yum
^^^
.. code-block:: python

   sudo yum install epel-release
   pip install twisted
   sudo yum install python-netifaces
   pip install M2Crypto
   sudo yum install libsodium-devel
   pip install pycrypto

Windows
-------

Check if you have the 32 bits version of python or the 64 bits version. You can use:

.. code-block:: python

   python -c "import struct;print( 8 * struct.calcsize('P'))"

32 bits
^^^^^^^

.. code-block:: python

   pip install twisted
   pip install netifaces
   pip install --egg M2CryptoWin32

   Microsoft Visual C++ Compiler for Python 2.7
http://aka.ms/vcpython27

   Download the latest msvc version of libsodium from https://download.libsodium.org/libsodium/releases/
   Extract libsodium.dll from LIBSODIUM_ROOT\x32\Release\v140\dynamic\ on your harddrive and add that directory to your path
   Test if it works with: python -c "import ctypes; ctypes.cdll.LoadLibrary('libsodium')"

   pip install pycrypto

64 bits
^^^^^^^

.. code-block:: python

   pip install twisted
   pip install netifaces
   pip install --egg M2CryptoWin64

   Download the latest msvc version of libsodium from https://download.libsodium.org/libsodium/releases/
   Extract libsodium.dll from LIBSODIUM_ROOT\x64\Release\v140\dynamic\ on your harddrive and add that directory to your path
   Test if it works with: python -c "import ctypes; ctypes.cdll.LoadLibrary('libsodium')"

   pip install pycrypto

Mac
---

.. code-block:: python

   pip install twisted
   pip install netifaces
   pip install M2Crypto
   brew install libsodium
   pip install pycrypto

Documentation
=============

To compile the documentation on your own you need:

.. code-block:: python

   pip install sphinx
   pip install sphinx-rtd-theme

You can read a precompiled version on `ReadTheDocs <https://dispersy.readthedocs.io/>`_
