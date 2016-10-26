#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

test -n "$MAKE" && make
test -n "$ENVLIST" && tox -e "$ENVLIST"
