package main

import (
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/common/hexutil"
	"github.com/cypherium/cypherBFT/rpc"
	cli "gopkg.in/urfave/cli.v1"
)

var (
	PortFlag = cli.StringFlag{
		Name:  "port",
		Usage: "--port 8001,8002",
		Value: "8000",
	}
	TimeFlag = cli.IntFlag{
		Name:  "time",
		Usage: "--time 5",
		Value: 5,
	}
	PasswdFlag = cli.StringFlag{
		Name:  "passwd",
		Usage: "--passwd 1",
		Value: "1",
	}
	TransPortFlag = cli.StringFlag{
		Name:  "trans",
		Usage: "--trans 8000",
		Value: "8000",
	}
	MinerPortFlag = cli.StringFlag{
		Name:  "miner",
		Usage: "--miner 8001,8002",
		Value: "",
	}
	RemoteFlag = cli.StringFlag{
		Name:  "ip",
		Usage: "--ip 461f9d24b10edca41c1d9296f971c5c028e6c64c@67.228.187.203:8000,01482d12a73186e9e0ac1421eb96381bbdcd4557@67.228.187.206:8001",
		Value: "",
	}
)

func main() {
	app := cli.NewApp()
	app.Name = "auto"
	app.Usage = ""
	app.Commands = []cli.Command{
		{
			Name:   "miner",
			Usage:  "--port '8000,8001'",
			Flags:  []cli.Flag{PortFlag},
			Action: auto_miner_start,
		},
		{
			Name:   "trans",
			Usage:  "--port 8000,--time 5, --passwd 1",
			Flags:  []cli.Flag{PortFlag, TimeFlag, PasswdFlag},
			Action: auto_trans,
		},
		{
			Name:   "stop",
			Usage:  "--trans 8000 --miner 8000",
			Flags:  []cli.Flag{TransPortFlag, MinerPortFlag},
			Action: auto_stop,
		},
		{
			Name:   "remote",
			Usage:  "--ip '461f9d24b10edca41c1d9296f971c5c028e6c64c@67.228.187.203:8000,01482d12a73186e9e0ac1421eb96381bbdcd4557@67.228.187.206:8001'",
			Flags:  []cli.Flag{RemoteFlag},
			Action: remote_miner_start,
		},
		{
			Name:   "accounts",
			Usage:  "",
			Flags:  []cli.Flag{PortFlag},
			Action: accounts,
		},
		{
			Name:   "reset",
			Usage:  "",
			Flags:  []cli.Flag{PortFlag},
			Action: reset_data,
		},
	}
	app.Run(os.Args)
}

// SendTxArgs represents the arguments to sumbit a new transaction into the transaction pool.
type sendTxArgs struct {
	From     common.Address  `json:"from"`
	To       *common.Address `json:"to"`
	Gas      *hexutil.Uint64 `json:"gas"`
	GasPrice *hexutil.Big    `json:"gasPrice"`
	Value    *hexutil.Big    `json:"value"`
	Nonce    *hexutil.Uint64 `json:"nonce"`
	// We accept "data" and "input" for backwards-compatibility reasons. "input" is the
	// newer name and should be preferred by clients.
	Data  *hexutil.Bytes `json:"data"`
	Input *hexutil.Bytes `json:"input"`
}

func reset_data(c *cli.Context) error {
	//s := c.String(PortFlag.Name)
	//ports := strings.Split(s, ",")
	//for _, sPort := range ports {
	//}
	cmds := []string{
		"rm -rf ../cypher/data1/cypher",
		"rm -rf ../cypher/data2/cypher",
		"rm -rf ../cypher/data3/cypher",
		"rm -rf ../cypher/data4/cypher",
		"rm -rf ../cypher/data5/cypher",
		"../cypher/cypher.exe init ../cypher/genesisTest.json --datadir ../cypher/data1",
		"../cypher/cypher.exe init ../cypher/genesisTest.json --datadir ../cypher/data2",
		"../cypher/cypher.exe init ../cypher/genesisTest.json --datadir ../cypher/data3",
		"../cypher/cypher.exe init ../cypher/genesisTest.json --datadir ../cypher/data4",
		"../cypher/cypher.exe init ../cypher/genesisTest.json --datadir ../cypher/data5",
	}
	for _, s := range cmds {
		ret, err := execCmd(s)
		fmt.Println(s, ret, err)
	}
	return nil
}

func accounts(c *cli.Context) error {
	s := c.String(PortFlag.Name)
	ports := strings.Split(s, ",")
	for _, sPort := range ports {
		client, err := rpc.Dial("http://localhost:" + sPort)
		if err != nil {
			fmt.Println("rpc.Dial err", err)
			return err
		}

		var accounts []string
		var result string
		// err = client.Call(&result, "personal_unlockAll", "1")

		err = client.Call(&accounts, "eth_accounts")
		if err != nil {
			fmt.Println("client.call:eth_accounts err", err)
			return err
		}
		for k, v := range accounts {
			if v != accounts[1] {
				to := common.HexToAddress(v)
				args := sendTxArgs{
					From:  common.HexToAddress(accounts[1]),
					To:    &to,
					Value: (*hexutil.Big)(big.NewInt(50000000000000000)),
				}
				err = client.Call(&result, "eth_sendTransaction", args)
				if err != nil {
					fmt.Println("client.call:eth_sendTransaction err", err)
					return err
				}
			}
			err = client.Call(&result, "eth_blockNumber")
			if err != nil {
				fmt.Println("client.call:eth_txBlockNumber err", err)
				return err
			}

			err = client.Call(&result, "eth_getBalance", v, string(result))
			if err != nil {
				fmt.Println("client.call:eth_getBalance err", err, "addr", v)
				return err
			}
			fmt.Println("index", k, "addr", v, "balance", result)
		}

	}
	return nil
}

func remote_miner_start(c *cli.Context) error {
	s := c.String(RemoteFlag.Name)
	remotes := strings.Split(s, ",")

	for _, remote := range remotes {
		remote = strings.Trim(remote, " ")
		if len(remote) == 0 {
			continue
		}

		r := strings.Split(remote, "@")

		dest := "http://" + r[1]
		client, err := rpc.Dial(dest)
		if err != nil {
			fmt.Println("rpc.Dial err", err)
			return err
		}

		var result string

		err = client.Call(&result, "miner_start", 1, r[0], "1")
		if err != nil {
			fmt.Printf("miner_start %s %v\n", remote, err)
		//	return err
		}
		fmt.Printf("miner start %s ok\n", remote)

	}

	return nil
}

func auto_miner_start(c *cli.Context) error {
	s := c.String(PortFlag.Name)
	ports := strings.Split(s, ",")
	for _, sPort := range ports {
		client, err := rpc.Dial("http://localhost:" + sPort)
		if err != nil {
			fmt.Println("rpc.Dial err", err)
			return err
		}

		var account []string
		var result string

		err = client.Call(&account, "eth_accounts")
		if err != nil {
			fmt.Println("client.call:eth_accounts err", err)
			return err
		}

		err = client.Call(&result, "miner_start", 2, account[0], "1")
		if err != nil {
			fmt.Println("client.call: miner_start err", err)
		//	return err
		}
		fmt.Println(sPort+" miner_start OK!", result)

	}

	return nil
}

func auto_trans(c *cli.Context) error {
	sPort := c.String(PortFlag.Name)
	client, err := rpc.Dial("http://localhost:" + sPort)
	if err != nil {
		fmt.Println("rpc.Dial err", err)
		return err
	}

	var result string
	sPwd := c.String(PasswdFlag.Name)
	err = client.Call(&result, "personal_unlockAll", sPwd)
	/*
		if err != nil {
			fmt.Println("client.call: personal_unlockAll err", err, "result", result)
			return err
		}
	*/
	time.Sleep(1000 * time.Millisecond)

	nTime := c.Int(PortFlag.Name)
	err = client.Call(&result, "eth_autoTransaction", 1, nTime)
	if err != nil {
		fmt.Println("client.call: eth_autoTransaction err", err)
		return err
	}
	fmt.Println(sPort+" eth_autoTransaction OK!", result)
	return nil

}

func auto_stop(c *cli.Context) error {
	sPort := c.String(TransPortFlag.Name)
	if sPort != "" {
		client, err := rpc.Dial("http://localhost:" + sPort)
		if err != nil {
			fmt.Println("rpc.Dial err", err)
			return err
		}

		//var account[]string
		var result string
		err = client.Call(&result, "eth_autoTransaction", 0, 5)
		if err != nil {
			fmt.Println("client.call: eth_autoTransaction(0,5) err", err)
			return err
		}
		fmt.Println(sPort+" eth_autoTransaction(0,5) stop OK! ", result)
	}

	s := c.String(MinerPortFlag.Name)
	if s != "" {
		ports := strings.Split(s, ",")
		for _, sPort := range ports {
			client, err := rpc.Dial("http://localhost:" + sPort)
			if err != nil {
				fmt.Println("rpc.Dial err", err)
				return err
			}

			//var account[]string
			var result string
			err = client.Call(&result, "miner_stop")
			if err != nil {
				fmt.Println("client.call: miner_stop err", err)
				return err
			}
			fmt.Println(sPort+" miner_stop OK!", result)
		}
	}

	return nil
}
func execCmd(cmdStr string) (string, error) {
	args := strings.Split(cmdStr, " ")
	cmd := exec.Command(args[0], args[1:]...)
	res, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(res), nil
}
