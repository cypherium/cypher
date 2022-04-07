#!/bin/sh

set -e

if [ ! -f "build/env.sh" ]; then
    echo "$0 must be run from the root of the repository."
    exit 2
fi

root="$PWD"
cphdir="$root/../cypher"

# Run the command inside the workspace.
cd "$cphdir"
PWD="$cphdir"

# Launch the arguments with the configured environment.
exec "$@"
