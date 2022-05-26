# gnunet-go: GNUnet implementation in Go

Copyright (C) 2019-2022 Bernd Fix  >Y<

gnunet-go is free software: you can redistribute it and/or modify it
under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License,
or (at your option) any later version.

gnunet-go is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

SPDX-License-Identifier: AGPL3.0-or-later

## Caveat

THIS IS WORK-IN-PROGRESS AT A VERY EARLY STATE. DON'T EXPECT ANY COMPLETE
DOCUMENTATION OR COMPILABLE, RUNNABLE OR EVEN OPERATIONAL SOURCE CODE.

## TL;DR

```bash
git clone https://github.com/bfix/gnunet-go
cd gnunet-go/src/gnunet
go mod tidy
go install -gcflags "-N -l" ./...
go test -gcflags "-N -l" ./...
```

## Source code

All source code is written for Go v1.18+.

3rd party libraries are managed by the Go module framework. After downloading
the source code, make sure you run `go mod tidy` in the `src/gnunet` folder
to install all dependencies.

### `./src/gnunet`

The folder `src/gnunet` contains a Go implementation of GNUnet: It is WIP
and only provides a very limited coverage of GNUnet. The goal is to have
a complete, functionally equivalent implementation of the GNUnet protocol
in Go. Currently only some aspects of Transport, GNS, Revocation, Namecache
and DHT are implemented.

Use `./build.sh` to build the executables (services and utilities, see
below). The resulting programs are stored in `${GOPATH}/bin`.

To run the unit tests, use `./test.sh`. 

### `./src/gnunet/cmd`

#### `gnunet-service-dht-test-go`: Implementation of the DHT core service (testbed).

#### `gnunet-service-gns-go`: Implementation of the GNS core service.

Stand-alone GNS service that could be used with other GNUnet utilities and
services.

#### `gnunet-service-revocation-go`: Implementation of the GNS revocation service.

Stand-alone Revocation service that could be used with other GNUnet utilities
and services.

#### `revoke-zonekey`: Implementation of a stand-alone program to calculate revocations.

This program creates a zone key revocation block. Depending on the parameters
the calculation can take days or even weeks. The program can be interrupted
at any time using `^C`; restarting the program with the exact same parameters
continues the calculation.

The following command-line options are available:

* **`-b`**: Number of leading zero bits (difficulty, default: 24). The minimum
difficulty `D` is fixed at 23. The expiration of a revocation is derived using
`(b-D+1)*(1.1*EPOCH)`, where `EPOCH` is 365 days and it is extended by 10% in
order to deal with unsynchronized clocks.

The default difficulty will create a revocation valid for ~2 years.

* **`-z`**: Zone key to be revoked (zone ID)

* **`-f`**: Name of file to store revocation data

* **`-t`**: testing mode: allow small difficulties for test runs.

* **`-v`**: verbose output

#### `peer_mockup`: test message exchange on the lowest level (transport).

#### `vanityid`: Compute GNUnet vanity peer id for a given regexp pattern.

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
echo "<hex.seed>" | xxd -r -p > /var/lib/gnunet/.local/share/gnunet/private_key.ecc
chown gnunet:gnunet /var/lib/gnunet/.local/share/gnunet/private_key.ecc
chmod 600 /var/lib/gnunet/.local/share/gnunet/private_key.ecc
```
