#!/bin/bash

go test $* -gcflags "-N -l" ./...
