#!/bin/bash

function compile() {
	GOPATH=$(pwd) go build -o bin/$1 src/cmd/$1/main.go
}

compile vanityid
compile gns_service

