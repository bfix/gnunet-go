#!/bin/bash

cd src/gnunet/
go install -v -gcflags "-N -l" ./...
