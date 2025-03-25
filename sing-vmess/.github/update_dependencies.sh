#!/usr/bin/env bash

PROJECTS=$(dirname "$0")/../..

go get -x github.com/newsingeng/sing@$(git -C $PROJECTS/sing rev-parse HEAD)
go mod tidy
