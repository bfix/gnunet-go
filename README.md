# GNUnet in Go

This repository has two parts:

* `src/` contains a Go implementation of GNUnet: It is WIP and only provides a
very limited coverage of GNUnet. The goal is to have a complete, functionally
equivalent implementation of the GNUnet protocol in Go.

* `doc/` contains documents for an implementation-agnostic specification of the
GNUnet P2P protocols. It focuses on the peer messages, but also provides
information on the internal messages.

## Author(s)
 * Bernd Fix <brf@hoi-polloi.org>

All files are licensed under GNU AGPL-3.0. Copyright by the authors.

## Caveat

THIS IS WORK-IN-PROGRESS AT A VERY EARLY STATE. DON'T EXPECT ANY COMPLETE
DOCUMENTATION OR COMPILABLE, RUNNABLE OR EVEN OPERATIONAL SOURCE CODE.

## Source code

All source code is written in Golang (version 1.11+).

### Dependencies

3rd party libraries are used to provide helper functionality (logging, MPI,
Ed25519 support and other crypto-related packages). Make sure the dependent
packages are accessible through `GOPATH`. To install the dependencies:

```bash
$ go get -u golang.org/x/crypto/...
$ go get -u golang.org/x/text/...
$ go get -u github.com/bfix/gospel/...
```

### ./src/cmd folder

* `vanityid`: Compute GNUnet vanity peer id for a given start pattern.

* `gnunet-service-gns-go`: Implementation of the GNS service.

* `peer_mockup`: test message exchange on the lowest level (transport).

### ./src/gnunet folder

Packages used to implement GNUnet protocols (currently only TRANSPORT
and GNS).

## Documentation

* papers: 3rd party papers on GNUnet and crypto (mostly academic)
* raw: raw ASCII protocol definition
* reports: findings in the GNUnet source code
* specification: texinfo protocol definition

