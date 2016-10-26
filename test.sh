#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

test -z "${MAKE:-}" || make
test -z "${ENVLIST:-}" || tox -e "$ENVLIST"
