#!/bin/bash

GOPATH=$(pwd):${GOPATH} go test -gcflags "-N -l" ./...
