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

All source code is written in Golang (version 1.13+).

### Dependencies

3rd party libraries are used to provide helper functionality (logging, MPI,
Ed25519 support and other crypto-related packages). Make sure the dependent
packages are accessible through `GOPATH`. To install the dependencies:

```bash
$ go get -u golang.org/x/crypto/...
$ go get -u golang.org/x/text/...
$ go get -u github.com/miekg/dns/...
$ go get -u github.com/bfix/gospel/...
```

### ./src/cmd folder


#### `gnunet-service-gns-go`: Implementation of the GNS service.

#### `peer_mockup`: test message exchange on the lowest level (transport).

#### `vanityid`: Compute GNUnet vanity peer and ego id for a given regexp pattern.

N.B.: Key generation is slow at the moment, so be patient! To generate a single
matching key some 1,000,000 keys need to be generated for a four letter prefix;
this can take more than 30 minutes on average (depending on your CPU).

```bash
$ vanityid "^TST[0-9]"
```

Keys matching the pattern are printed to the console in the following format:

```bash
<vanity_id> [<hex.seed>][<hex.scalar>] (<count> tries, <time> elapsed)
```
The value of `count` tells how many key had been generated before a match was
found; `time` is the time needed to find a match.

To generate the key files, make sure GNUnet **is not running** and do: 

```bash
$ # use a vanity peer id:
$ echo "<hex.seed>" | xxd -r -p > /var/lib/gnunet/.local/share/gnunet/private_key.ecc
$ sudo chown gnunet:gnunet /var/lib/gnunet/.local/share/gnunet/private_key.ecc
$ sudo chmod 600 /var/lib/gnunet/.local/share/gnunet/private_key.ecc
$ # use a vanity ego id:
$ echo "<hex.scalar>" | xxd -r -p > ~/.local/share/gnunet/identity/egos/<vanity_ego>
$ chmod 600 ~/.local/share/gnunet/identity/egos/<vanity_ego>
```
### ./src/gnunet folder

Packages used to implement GNUnet protocols (currently only some of TRANSPORT
and GNS).

## Documentation

* papers: 3rd party papers on GNUnet and crypto (mostly academic)
* raw: raw ASCII protocol definition
* reports: findings in the GNUnet source code
* specification: texinfo protocol definition

