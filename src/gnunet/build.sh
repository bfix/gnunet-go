#!/bin/bash

if [ "$1" = "withgen" ]; then
    go generate ./...
    shift
fi

TAG=$(git tag --sort -taggerdate | head -n 1)

go install $* -trimpath -gcflags "-N -l -trimpath $(pwd)=>gnunet@${TAG}" ./...
