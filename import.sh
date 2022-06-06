#!/bin/bash

TOP_PID=$$
CYPHER="./cmd/cypher/cypher"
NODES_NUM=$1

echo "begin importing"
for n in $( seq $NODES_NUM ); do
    echo "importing $n -------------------------------------------------------------------"
    sleep .2
    $CYPHER importChain  --datadir ./localChaindb/$n  --from ../cypherBFT/localChaindb/$n
done
echo "end!"
