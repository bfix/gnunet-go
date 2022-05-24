#!/bin/bash

cd src/gnunet/
go test $* -gcflags "-N -l" ./...
