cypher Tutorial
===

Public iP for VPS is needed
--
Your ip of your machine or VPS which used to deploy cypher node  must be `public IP`.such AWS ec2 which has `public IP` to deploy your cypher node!
Please open 8000,6000,9090,7100 ports for UDP and TCP rule for VPS.

go version and module
--
To build the source,you need to install go1.18.1 language.
 ```
wget https://dl.google.com/go/go1.18.1.linux-amd64.tar.gz
tar -C /usr/local -zxvf go1.18.1.linux-amd64.tar.gz
go env -w GO111MODULE=off
 ```
Bls crypto gmplib 
--
 ``` 
apt-get update && apt-get install -y gcc cmake libssl-dev openssl libgmp-dev bzip2 m4 build-essential git curl gcc libc-dev wget texinfo

wget https://ftp.gnu.org/gnu/gmp/gmp-6.1.2.tar.bz2
tar -xjf gmp-6.1.2.tar.bz2
cd gmp-6.1.2
./configure --prefix=/usr --enable-cxx --disable-static --docdir=/usr/share/doc/gmp-6.1.2
sudo make  
sudo make html  
sudo make check  
sudo make install  
sudo make install-html 
sudo cp -rf /usr/lib/libgmp* /usr/local/lib/
 ``` 
Install the openssl
--

for linux
 ```
sudo apt-get install openssl
sudo apt-get install libssl-dev
 ```
for mac:
 ```
git clone https://github.com/openssl/openssl
cd openssl
sudo ./config --prefix=/usr/local/openssl
make
make install
openssl version
 ```
Download repository
---
 We suggest you switch your computer account to root account
 #### 1. Install Git:
   for linux,run follow command:
    ```
   sudo apt-get install git  
    ```

   for mac,visit follow URL to install:
    ```
    http://sourceforge.net/projects/git-osx-installer/
    ```
 #### 2. Open the terminal and clone repository:
 ```
  git clone https://github.com/cypherium/cypher.git
  cd cypher
  ls
  make cypher
 ```
Tips:according to you system,please copy `./crypto/bls/lib/yoursystem/*` to `./crypto/bls/lib/` for bls library.

 Run the cypher
 ---

 #### init database
 ```
./build/bin/cypher --datadir chaindbname init ./genesis.json
 ```
 #### run node
 ```
./build/bin/cypher --verbosity 4 --rnetport 7100 --syncmode full  --nat="none --ws --ws.addr="0.0.0.0" --ws.port 8546  --ws.origins "*" --http.corsdomain "*" --http.addr 0.0.0.0 --http --http.api eth,web3,net,miner,txpool --port 6000 --http.port 8000 --targetgaslimit "3758096384" --datadir chaindbname --networkid 16166 --gcmode archive --datadir chaindbname --bootnodes enode://a294a4d23b3c0671eac267ae0df03487e79ae58f52b668514e3510a292a13853dd3070deb6f703fe2c92a68609fcfd603cd6e7cf6ddb418fa523612285219293@218.185.241.185:30301 console
 ```
 #### start up parameters help
    
   The IPC interface is enabled by default and exposes all the APIs supported by `cypher`,
    whereas the HTTP and WS interfaces need to manually be enabled and only expose a
    subset of APIs due to security reasons. These can be turned on/off and configured as
    you'd expect.
    
   HTTP based JSON-RPC API options:
    
   * `--addr` HTTP-RPC server listening interface (default: `localhost`)
   * `--rpcport` HTTP-RPC server listening port (default: `8000`)
   * `--port` P2P listening port (default: `6000`)
   * `--api` API's offered over the HTTP-RPC interface (default: `eth,net,web3`)
   * `--corsdomain` Comma separated list of domains from which to accept cross origin requests (browser enforced)
   * `--ws` Enable the WS-RPC server
   * `--wsaddr` WS-RPC server listening interface (default: `localhost`)
   * `--wsport` WS-RPC server listening port (default: `8000`)
   * `--wsorigins` Origins from which to accept websockets requests
   * `--rpcapi` API's offered over the IPC-RPC interface (default: `admin,debug,eth,miner,net,personal,shh,txpool,web3`)
   * `--ipcpath` Filename for IPC socket/pipe within the datadir (explicit paths escape it)
   * `--nat value`  NAT port mapping mechanism (any|none|upnp|pmp|extip:<IP>) (default: "any")
   * `--rnetport` Committee consensus port(default: `7100`)
   * `--verbosity` Output log level,max value is 6(default: `4`)
   * `--datadir` Data directory for the databases and keystore
   * `--networkid` Network identifier (16162=mainNet)
   * `--datadir` Blockchain garbage collection mode ("full", "archive") (default: "full")
   * `--bootnodes`  The first time a node connects to the network it uses one of the predefined bootnodes. Through these bootnodes a node can join the network and find other nodes.
   * `--mine`  Enable mining	
   * `--console` Start an interactive JavaScript environment
    
   You'll need to use your own programming environments' capabilities (libraries, tools, etc) to
   connect via HTTP, WS or IPC to a `cypher` node configured with the above flags. You
   can reuse the same connection for multiple requests!
    
   **Note: Please understand the security implications of opening up an S based
   transport before doing so! Hackers on the internet are actively trying to subvert
   Cypherium nodes with exposed APIs! Further, all browser tabs can access locally
   running web servers, so malicious web pages could try to subvert locally available
   API
    
Congratulations! You have started cypherium node successfully!

With the database up and running, try out these commands
--

#### 1. eth.txBlockNumber
Check the transaction block height.
#### 2. personal.newAccount("cypher2019xxddlllaaxxx")
New one account,Among " " your should assign one password.

#### 3. net
List the peer nodes's detail from  P2P network.
#### 4. admin.peers
List the number of peer nodes from  P2P network.
#### 5. eth.accounts
List all the accounts
#### 6. eth.getBalance(...)
Get the balance by specify one account.
eth.getBalance("0x2dbde7263aaaf1286b9c41b1138191e178cb2fd4")
   The string of “ 0x2dbde7263aaaf1286b9c41b1138191e178cb2fd4” is your wallet account.
This wallet account string you shoud copy and store it when you executiong comand
 “ personal.newAccount(...) “; also your can using command “ eth.accounts ” to find if from  serveal acccounts.

Txpool
--
#### 1. txpool.status
List count of pending and queued transactions.
#### 2. txpool.content
List all transactions int txpool.


Manual send transaction demonstration
--
#### 1. Guarantee you have two account
Check this through “eth.accounts”.If you do not have,please new two accouts by using comand “ personal.newAccount() “
#### 2. check your account balance
```
 eth.getBalance("0x461f9d24b10edca41c1d9296f971c5c028e6c64c")
 eth.getBalance("0x01482d12a73186e9e0ac1421eb96381bbdcd4557")
```
#### 3. unlock your account
```
personal.unlockAccount("0x461f9d24b10edca41c1d9296f971c5c028e6c64c")
```
#### 4. sendTransaction
```
eth.sendTransaction({from:'461f9d24b10edca41c1d9296f971c5c028e6c64c',to: '01482d12a73186e9e0ac1421eb96381bbdcd4557', value: 1000000000000000000})
```
#### 5. wait several seconds to checkout balance
```
 eth.getBalance("0x461f9d24b10edca41c1d9296f971c5c028e6c64c")
 eth.getBalance("0x01482d12a73186e9e0ac1421eb96381bbdcd4557")
```
RUN:Operator miner functions
---
#### 1. miner.start(1, "0x2dbde7263aaaf1286b9c41b1138191e178cb2fd4")
First param 1 is for threads accord to you computer power;Second param is "0x2dbde7263aaaf1286b9c41b1138191e178cb2fd4" is your account.You must be enter your password.


#### 2. miner.status()
After miner.start(),your can check your current status or your current node role by using function for miner.status():

You will wait minimum 1 hour to check with command function for miner.status() to confirm whether your node have been promoted successfully.
If you are node accounts status is "I'm committee member, Doing consensus." or "I'm leader, Doing consensus."your account have been chosen into committee successfully:


Finally,after waiting about 1 hour you can check you account’s balance through function for eth.getBalance()
#### 3. miner.content()
You can check miner’s candidate from yourself and other nodes.


#### 4. miner.stop()
Stop the to find candidate to take part in consensus.

More APIs
---
[ref eth apis](https://geth.ethereum.org/docs)

Example scripts to run cypher quickly
---
You can copy the `./build/bin/cypher` to the [cypher-bin](https://github.com/cypherium/cypher-bin.git) repo's corresponding directory such as `linux or darwin`

