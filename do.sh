#!/bin/bash

TOP_PID=$$
CYPHER="./cmd/cypher/cypher"
GENESIS="./genesisLocal.json"
NODE_DIR="localChaindb"
#NODE_DIR="localChaindb"
NODES_MAX=100
NODES_NUM=0
ACCOUNTSLIST="$NODE_DIR/accounts.txt"
LOGLEVEL=5
# Commands
CLEANDB="cleandb"
INIT="init"
CLEAN="clean"
CLDBF="clnode"
APPEND="append"
CONSOLE="cs"
RESTART="csr"
ATTACH="attach"
STOP="stop"
NEWACCOUNT="newAccount"
LISTACCOUNT="listAccount"
IPENCDISVALUE=1
PRMV=1
EnableFlags=""   


cd cmd/cypher
go build
cd ../..
