# GNUnet protocol specification

Implementation-agnostic specification of GNUnet P2P protocols

Author: Bernd Fix

All files are licensed under GNU AGPL-3.0.

THIS IS WORK-IN-PROGRESS AT A VERY EARLY STATE. DON'T EXPECT ANY COMPLETE
DOCUMENTATION OR COMPILABLE, RUNNABLE OR EVEN OPERATIONAL SOURCE CODE.

## Documentation

* papers: 3rd party papers on GNUnet and crypto (mostly academic)
* raw: raw ASCII protocol definition
* reports: findings in the GNUnet source code
* specification: texinfo protocol definition

## Source code

All source code is written in Golang (version 1.10+) without additional
3rd party libraries (although some source code files from
[https://github.com/bfix/gospel] are re-used).

### ./src/cmd folder

* vanityid: Compute GNUnet vanity peer id
* peer_mockup: Golang-based peer to test message exchange

### ./src/gnunet folder

Packages used to implement GNUnet protocols (currently only TRANSPORT)

