#!/bin/bash


changed=0

function update() {
    rc=$(diff "$1" "$2")
    if [ -n "$rc" ]; then
        cp "$2" "$1"
        echo "Updated registry file '$1' from '$2'"
        changed=1
    else
        echo "Up-to-date registry file '$1'"
    fi
}

# Synchronize GANA definitions

REPO=../../../gana

pushd $REPO
git pull
popd

update enums/gnunet-signature.rec $REPO/gnunet-signatures/registry.rec
update enums/gnunet-dht.rec $REPO/gnunet-dht-block-types/registry.rec
update enums/gnunet-gns.rec $REPO/gnu-name-system-record-types/registry.rec
update enums/gnunet-error-codes.rec $REPO/gnunet-error-codes/registry.rec

if [ $changed -eq 1 ]; then
    go generate ./...
fi
