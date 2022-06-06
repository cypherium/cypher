#!/bin/bash

TOP_PID=$$
#DATE=`date +"%m%d-%H:%M"`
#LOGDIR="LOG-`date +"%m%d-%H:%M"`"
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


rm -rf "$LOGDIR"
mkdir -p "$LOGDIR"

for m in $( seq $NODES_NUM ); do
    cp -f "$m/$m.digest.log" "$LOGDIR"
done

tar -czvf "$LOGDIR.tar.gz" "$LOGDIR"

rm -rf "$LOGDIR"