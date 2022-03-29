#!/bin/bash
port=30301
#localip=`ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:"​`
#localip=`echo $localip|awk '{print $1}'`
localip=127.0.0.1
echo "local ip:$localip,port:$port"
kill -9 $(lsof -i:$port |awk '{print $2}' | tail -n 2)
./bootnode  -addr "$localip:$port" -nodekey=local.key
