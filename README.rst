********
Dispersy
********

The **Dis**\ tributed **Per**\ mission **Sy**\ stem, or Dispersy, is a platform to simplify the design of distributed
communities. At the heart of Dispersy lies a simple identity and message handling system where each community
and each user is uniquely and securely identified using elliptic curve cryptography.

Integrated NAT Puncturing
=========================

Nowadays almost all devices have a network connection, with a lot of them running in challenged network environments.
Challenging conditions can be found in a wide range of networks, i.e. Peer-to-Peer networks (P2P), and delay tolerant networks (DTNs). These networks have several
limitations, like having long communication delays, very low data rates, and unstable links.

P2P networks are particularly challenging due to nodes not always being online, NAT-firewall constrained Internet
connections, and frequent interaction with potentially malicious nodes. Smartphones pose another challenge due to
their limited processing capability and battery lifetime.

Dispersy was designed to be capable of running in challenged network environments. It does this by minimizing
the needed resources by using optimized algorithms and protocols.

Decentralized
=============

Dispersy is fully decentralized. It does not require any server infrastructure and can run on systems consisting of
a large number of nodes. Each node runs the same algorithm and performs the same tasks. All nodes are equally important,
resulting in increased robustness. Dispersy offers distributed system developers both one-to-many and many-to-many data
dissemination capabilities. Data is forwarded between nodes. All injected data will eventually reach all nodes,
overcoming challenging network conditions.

Dispersy uses elliptic curve cryptography to identify the different nodes in a secure and anonymous way.

Goal
====

Dispersy is designed as a building block for implementing fully decentralized versions of, for instance Facebook,
Wikipedia, Twitter, or Youtube. These Web 2.0 applications often require on a direct Internet connection to their
central servers, but can now be implemented in a distributed way

Key Features
============

Key features of Dispersy are:

* stateless synchronization using Bloomfilters
* decentralized NAT traversal
* performance that can scale to over 100,000 bundles

Dispersy is intergated in the BitTorrent client Tribler and show that
it is performing very well in various real-time challenged network scenario’s (3G and WIFI).

Documentation
=============

The documentation for this project can be found at `ReadTheDocs <https://dispersy.readthedocs.io/>`_