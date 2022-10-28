#!/bin/bash

if [ "$1" = "withgen" ]; then
    go generate ./...
    shift
fi

go install $* -trimpath -gcflags "-N -l" ./...
