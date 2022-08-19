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

Go v1.18+ is required to compile the code.

```bash
git clone https://github.com/bfix/gnunet-go
cd gnunet-go/src/gnunet
go mod tidy
go generate ./...
go install ./...
go test ./...
```

The binaries are stored in `${GOPATH}/bin`.

# Source code

All source code is written for Go v1.18+.

3rd party libraries are managed by the Go module framework. After downloading
the source code, make sure you run `go mod tidy` in the `src/gnunet` folder
to install all dependencies.

## `./src/gnunet`

The folder `src/gnunet` contains a Go implementation of GNUnet: It is WIP
and only provides a very limited coverage of GNUnet. The goal is to have
a complete, functionally equivalent implementation of the GNUnet protocol
in Go. Currently only some aspects of Transport, GNS, Revocation, Namecache
and DHT are implemented.

Use `./build.sh withgen` to build the executables (services and utilities, see
below). The resulting programs are stored in `${GOPATH}/bin`.

To run the unit tests, use `./test.sh`. 

## `./src/gnunet/enums`

Changes in GANA definitions for block types, GNS record types and signature
purpose values can be imported by copying the recfiles (GNU recutils) from
GANA into this folder:

* gnunet-dht.rec
* gnunet-gns.rec
* gnunet-signature.rec

After updating the recfiles, you need to run `go generate ./...` to generate
the new source files.

## `./src/gnunet/cmd`

### `gnunet-service-dht-test-go`: Implementation of the DHT core service (testbed).

### `gnunet-service-gns-go`: Implementation of the GNS core service.

Stand-alone GNS service that could be used with other GNUnet utilities and
services.

### `gnunet-service-revocation-go`: Implementation of the GNS revocation service.

Stand-alone Revocation service that could be used with other GNUnet utilities
and services.

### `revoke-zonekey`: Implementation of a stand-alone program to calculate revocations.

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

### `peer_mockup`: test message exchange on the lowest level (transport).

### `vanityid`: Compute GNUnet vanity peer id for a given regexp pattern.

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

For `gnunet-go` configuration files you need to paste the result of
`echo "<hex.seed>" | xxd -r -p | base64` into the `PrivateSeed` field in the
`NodeConfig` section.

# Testing `gnunet-go`

To test the current `gnunet-go` implementation in a local GNUnet environment,
you should follow the detailed instructions below.

**N.B.**: Testing requires an up-to-date GNUnet build from source. You can
either use your local machine (please follow the GNUnet documentation for
setup) or you can simply use a Docker image like
[gnunet-docker](https://github.com/bfix/gnunet-docker) for this.

## Testing `R5N DHT`

`gnunet-go` implements the DHT protocol specified in
[lsd0004](https://lsd.gnunet.org/lsd0004/) and uses a custom (unencrypted)
transport protocol not supported by the standard GNUnet. Luckily there is a
testbed in GNUnet that allows to run the new protocol over UDP/IP.

### Starting the DHTU testbed

Make sure you stopped (or have not started) all GNUnet services; the testbed
will take care of everything required.

Change into `./src/dht` in the `gnunet`-Repository and start any number of
DHTU nodes for testing:

```bash
./dhtu_testbed_deploy.sh 10
```

will start ten DHTU nodes. Nodes will listen to all available network
addresses on port 10000+ (one node, one port).

Log and configuration files can be found in `/tmp/deployment/`; they are
named by index (starting at 0).

### Running the `gnunet-go` node in the testbed

#### Setting up the configuration file

Copy the example `gnunet-config.json` to `dhtu-config.json` and modify the
`network` and `local` sections to our local setup. In this example
`172.17.0.5` is the network address for GNUnet DHTU nodes and `172.17.0.1`
is the network address for `gnunet-go`:

```json
{
    "network": {
        "bootstrap": [
            "ip+udp://127.17.0.5:10000"
        ],
        "numPeers": 10
    },
    "local": {
        "privateSeed": "YGoe6XFH3XdvFRl+agx9gIzPTvxA229WFdkazEMdcOs=",
        "endpoints": [
            {
                "id": "r5n",
                "network": "ip+udp",
                "address": "172.17.0.1",
                "port": 2086,
                "ttl": 86400
            }
        ]
    }
    :
}
```

The above configuration will expect a network of 10 nodes and has a single
bootstrap node (the first DHTU node in the testbed). `gnunet-go` will listen
on port 2086.

#### Running the `gnunet-go`node

Run the following commands to start the `gnunet-go` node:

```bash
rm -rf /tmp/gnunet-system-runtime
mkdir -p /tmp/gnunet-system-runtime
${GOPATH}/bin/gnunet-service-dht-go -c dhtu-config.json 2>&1 | tee run.log
```

## Testing `GNS`

**N.B.**: The GNS service is currently not up-to-date. To test it, you need to
check out version v0.1.23 (the latest tested version) and a matching GNUnet
version as well (latest as of May 2020) to be on a safe side. You also need to
have (all) GNUnet services up and running.

### Setting up a modified configuration for GNUnet

You need to tell the GNUnet client which GNS service to use (either the default
or the `gnunet-go` version) by modifying the GNS service socket. Copy your
configuration file to `gns-go.comf` and modify the `[gns]` sectiom:

```
UNIXPATH = $GNUNET_RUNTIME_DIR/gnunet-service-gns-go.sock
```

This will ensure that clients (and other services) talk to the `gnunet-go`
GNS service.

### Setting up the configuration file (gnunet-go)

Copy the example `gnunet-config.json` to `gns-config.json` and modify the
`network` and `local` sections:

```json
{
    "network": {
        "bootstrap": [],
        "numPeers": 10
    },
    "local": {
        "privateSeed": "YGoe6XFH3XdvFRl+agx9gIzPTvxA229WFdkazEMdcOs=",
        "endpoints": []
    },
    :
}
```

### Preparing and running the tests

For test purposes you need to start the `gnunet-go` DNS service, generate
zones and resource records for testing and run the actual test cases.
You can use the follwing script to do it all in one go:

```bash
#!/bin/bash

GNS_SOCK=/tmp/gnunet-system-runtime/gnunet-service-gns-go.sock
[ -e ${GNS_SOCK} ] && sudo rm -f ${GNS_SOCK}
sudo -u gnunet ../bin/gnunet-service-gns-go -L 5 &
GOGNS=$!

function get_pkey() {
    gnunet-identity -d -e $1 | sed 's/.* - //'
}

CERT=$(openssl x509 -in <(openssl s_client -connect gnunet.org:443 </dev/null 2>/dev/null) -outform der \
    | od -t x1 -A n \
    | tr "\n" " " \
    | sed "s/ //g")
VPN="ZH7W4PR933913VA45AH45GH9QNQVP3TEM89J18549Q6RNDV75A4G secret"


for x in zone9 private; do
    gnunet-identity -D $x
done

  gnunet-identity -C zone9
  gnunet-identity -C private

  gnunet-namestore -a -z zone9   -n "@"  -t NICK    -V "zone9"                  -e never
  gnunet-namestore -a -z zone9   -n web  -t A       -V 131.159.74.67            -e never
  gnunet-namestore -a -z zone9   -n web  -t BOX     -V "6 443 52 3 0 0 ${CERT}" -e never
  gnunet-namestore -a -z zone9   -n gn   -t CNAME   -V gnunet.org               -e never
  gnunet-namestore -a -z zone9   -n sec  -t VPN     -V "6 ${VPN}"               -e never
  gnunet-namestore -a -z zone9   -n prv  -t PKEY    -V "$(get_pkey private)"    -e never
# gnunet-namestore -a -z zone9   -n prv  -t A       -V "14.15.16.17"            -e never
  gnunet-namestore -a -z zone9   -n old  -t LEHO    -V "old.gnunet.org"         -e never
  gnunet-namestore -a -z zone9   -n old  -t A       -V 5.6.7.8                  -e never
# gnunet-namestore -a -z zone9   -n old  -t A       -V 10.11.12.13              -e never
# gnunet-namestore -a -z zone9   -n old  -t TXT     -V "Old version"            -e never

  gnunet-namestore -a -z private -n "@"  -t NICK    -V "nexus9"                 -e never
  gnunet-namestore -a -z private -n name -t TXT     -V "GNUnet test"            -e never
  gnunet-namestore -d -z private -n host
  gnunet-namestore -a -z private -n host -t GNS2DNS -V "gnunet.org@8.8.8.8"     -e never
# gnunet-namestore -a -z private -n host -t A       -V 1.2.3.4                  -e never

function test_gns() {
    echo "========================"
    echo -n "Testing '$2' for type '$1': "
    gnunet-gns -t $1 -u $2 > plain.out
    gnunet-gns -c gns-go.conf -t $1 -u $2 > go.out
    rc=$(diff plain.out go.out)
    if [ -z "$rc" ]; then
        echo "O.K."
    else
        echo "FAILED!"
        echo "---------------- GNS-C"
        cat plain.out
        echo "---------------- GNS-Go"
        cat go.out
    fi
}

# (1)
test_gns any  web.zone9
# (2)
test_gns any  _443._tcp.web.zone9
# (3)
test_gns nick zone9
# (4)
test_gns any  gn.zone9
# (5)
test_gns any  sec.zone9
# (6)
test_gns pkey prv.zone9
# (7)
test_gns nick prv.zone9
# (8)
test_gns any  name.prv.zone9
# (9)
test_gns any  host.prv.zone9
# (10)
test_gns a  host.prv.zone9

kill ${GOGNS}
```

# Using gnunet-go in your own projects

`gnunet-go` is not a standard Go module for direct use (via go.mod) in other
packages, but designed as a stand-alone application. The rationale behind was
to **not** hard link the code to a single Git provider.

If you are interested in using (parts of) `gnunet-go` in your own projects, the
following step-by-step instructions show the easiest route.

* `git clone https://github.com/bfix/gnunet-go` into folder
`/home/user/gnunet-go` (or any other folder if you adjust the instructions
accordingly).

* create project folder and change into it
* run `go mod init test` (replace test with the name of your project)
* create a simple test `main.go`

```go
package main

import (
    "crypto/rand"
    "fmt"
    "gnunet/util"
)

func main() {
    a := make([]byte, 32)
    rand.Read(a)
    fmt.Println(util.EncodeBinaryToString(a))
}
```

* edit `go.mod` and add at end of file:

```bash
require gnunet v0.1.27

replace gnunet v0.1.27 => /home/user/gnunet-go/src/gnunet
```

* run `go mod tidy`
* build test program: `go build`
* run test program: `./test`

The only disadvantage of this approach is that you have to update the source
code for `gnunet-go` yourself. From time to time or on demand, do a `git pull`
followed by a `go mod tidy` described above. No version control is supported
either because the dependency for `gnunet-go` is redirected to a local folder.
