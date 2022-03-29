
PRIVATE_CONFIG=ignore ./cypher --datadir data --nodiscover --verbosity 5 --networkid 31337 --raft --raftport 50001 --http --http.addr 0.0.0.0 --http.port 8001 --http.api admin,db,eth,debug,miner,net,shh,txpool,personal,web3,quorum,raft --allow-insecure-unlock --emitcheckpoints --port 20001 --ipcpath cypher.ipc

raft.addPeer('enode://7cbc59085819a59b28fc4c5515378fbd121fec17edb6ae13362ff5e0546389683e95b2d49002fd83aceb2dd7d14416671b986430790c20356472481989d5dd64@127.0.0.1:20002?discport=0&raftport=50002')


PRIVATE_CONFIG=ignore ./cypher --datadir data1 --nodiscover --verbosity 5 --networkid 31337 --raft --raftport 50002 --http --http.addr 0.0.0.0 --http.port 8002 --http.api admin,db,eth,debug,miner,net,shh,txpool,personal,web3,quorum,raft --allow-insecure-unlock --emitcheckpoints --port 20002 --ipcpath geth1.ipc

raft.addPeer('enode://428bc30b639546709fb6cd94ea764491eb475547cbee633909666a1fd395341aef148bdd83dbc52485c2869c7a6ce2e0a445a241636cef222214a466104f62ea@127.0.0.1:20001?discport=0&raftport=50001')



eth.sendTransaction({from: eth.accounts[0], to: '0x403C18004054a745a83A7AC94f9C2fb4A7446F89', value: 16200000000000000})


	account := accounts.Account{Address: addr.Address()}
	wallet, err := api.am.Find(account)
	if err != nil {
		return nil, err
	}
	// Assemble sign the data with the wallet
	signature, err := wallet.SignHashWithPassphrase(account, res.Password, sighash)
	if err != nil {
		api.UI.ShowError(err.Error())
		return nil, err
	}
	signature[64] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper


	for _, wallet := range api.e.AccountManager().Wallets() {
		for _, account := range wallet.Accounts() {
			if account.Address == eb {
				//wallet.GetPubKey(account, passwd)
				pubKey, prvKey, err = wallet.GetKeyPair(account, password)
				if err != nil {
					log.Error("Cannot start reconfig without public key of coinbase", "err", err)
					return fmt.Errorf("Coinbase missing public key: %v", err)
				}
				server.Public = common.HexString(pubKey)
				server.Private = common.HexString(prvKey)
			}
		}
	}

	if pubKey == nil || prvKey == nil {
		log.Error("Cannot start reconfig without correct public key")
		return errors.New("missing public key")
	}
	log.Warn("pubKey", "pubKey", server.Public, "prvKey", server.Private)
	log.Warn("exip", "ip", api.e.ExtIP(), "port", api.e.config.RnetPort)
	server.Ip = api.e.ExtIP().String()
	server.Port = api.e.config.RnetPort
	api.e.reconfig.Start(server)

==============================================================================================
"args": [
	"--datadir","data", "--nodiscover","--verbosity", "5","--networkid", "31337", "--port", "21000",
	"--raft", "--raftport", "50000","--http", "--http.addr", "0.0.0.0", "--http.port", "22000",
	"--http.api", "admin,db,eth,debug,miner,net,shh,txpool,personal,web3,quorum,raft", "--emitcheckpoints"                
], // 启动参数



