#!/bin/bash

TOP_PID=$$
LOGDIR="logs"

log()
{
    echo 1>&2 "$1"
}

die()
{
    log "$1"
    kill -s TERM $TOP_PID
}

die_usage()
{
    log "Usage: $0 <number_of_nodes>"
    die
}

[ "$#" -eq 0 ] && die_usage

NODES_NUM=$1
if ! [[ "$NODES_NUM" =~ ^[1-9][0-9]*$ ]];then
    die "Invalid nodes number."
fi

LINES_NUM=$2
if ! [[ "$LINES_NUM" =~ ^[1-9][0-9]*$ ]];then
    die "Invalid lines number."
fi

for m in $( seq $NODES_NUM ); do
    tail -n $LINES_NUM $m/$m.log > $m/$m.digest.log
done
