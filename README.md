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

## Source code

All source code is written for Go v1.18+.

The folder `src/` contains a Go implementation of GNUnet: It is WIP and only
provides a very limited coverage of GNUnet. The goal is to have a complete,
functionally equivalent implementation of the GNUnet protocol in Go.

### Dependencies

3rd party libraries are managed by the Go module framework. After downloading
the source code, make sure you run `go mod tidy` to install all dependencies.

### ./src/gnunet/cmd folder


#### `gnunet-service-dht-test-go`: Implementation of the DHT core service (testbed).

#### `gnunet-service-gns-go`: Implementation of the GNS core service.

#### `gnunet-service-revocation-go`: Implementation of the GNS revocation service.

#### `revoke-zonekey`: Implementation of a stand-alone program to calculate revocations.

This program creates a zone key revocation block. Depending on the parameters
the calculation can take days or even weeks. The program can be interrupted
at any time using `^C`; restarting the program with the exact same parameters
continues the calculation.

The following command-line options are available:

* **`-b`***: Number of leading zero bits (difficulty, default: 25). The minimum
average difficulty `D` is fixed at 22. The expiration of a revocation is
derived using `(b-D) * (1.1 * EPOCH)`, where `EPOCH` is 365 days and it is
extended by 10% in order to deal with unsynchronized clocks.

The default difficulty will create a revocation valid for ~3 years.

* **`-z`**: Zone key to be revoked (zone ID)

* **`-f`**: Name of file to store revocation data

* **`-v`**: verbose output


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

Packages used to implement GNUnet protocols (currently only some of TRANSPORT, GNS,
Revocation, Namecache and DHT).
