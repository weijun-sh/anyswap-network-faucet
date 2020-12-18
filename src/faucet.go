// Copyright 2017 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// faucet is a Fusion faucet backed by a light client.
package main

//go:generate go-bindata -nometadata -o website.go faucet.html
//go:generate gofmt -w -s website.go

//USAGE: keysdir is ~/.faucet/keys
//startup: ./faucet --key KEYSTOREFILE --password passwd
//startup: ./faucet --webport 8880 --rpcport 8701 --key KEYSTOREFILE --password passwd

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/FusionFoundation/efsn/accounts"
	"github.com/FusionFoundation/efsn/accounts/keystore"
	"github.com/FusionFoundation/efsn/common"
	"github.com/FusionFoundation/efsn/common/hexutil"
	"github.com/FusionFoundation/efsn/core/types"
	"github.com/FusionFoundation/efsn/ethclient"
	"github.com/FusionFoundation/efsn/log"
	"github.com/FusionFoundation/efsn/rpc"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"golang.org/x/net/websocket"
)

const (
	chainID   = 202011
	webPort   = 8880
	rpcPort   = 12342
	rpcServer = "127.0.0.1"
	gateWay   = "https://rpc.smpc.network"
)

var (
	// required
	accJSONFlag = flag.String("key", "", "Key json file to fund user requests with")
	accPassFlag = flag.String("password", "", "Decryption password to access faucet funds")

	// optional
	rpcServerFlag = flag.String("server", rpcServer, "Connect server IP")
	webPortFlag   = flag.Int("webport", webPort, "Listener port for the HTTP API connection")
	rpcPortFlag   = flag.Int("rpcport", rpcPort, "Listener port for the rpc connection")
	logFlag       = flag.Int("verbosity", 3, "Log level to use for Fusion and the faucet")
)

var (
	ks      *keystore.KeyStore
	account accounts.Account

	faucetDbPath    = "~/.faucet/faucet.db"
	refreshInterval = 5 * time.Minute
	quotaNumber     = uint64(1000)
	faucetdb        *faucet
	refresh         = time.NewTicker(refreshInterval)
	refreshDone     = make(chan struct{})
	dbTime          = ""

	coinNum = new(big.Int).Mul(big.NewInt(20), big.NewInt(1000000000000000000))
)

type faucet struct {
	mutex sync.Mutex // protects db
	db    *leveldb.DB
	size  uint64
}

func init() {
	db, err := leveldb.OpenFile(faucetDbPath, nil)
	if _, corrupted := err.(*errors.ErrCorrupted); corrupted {
		db, err = leveldb.RecoverFile(faucetDbPath, nil)
	}
	// (Re)check for errors and abort if opening of the db failed
	if err != nil {
		fmt.Printf("Open file %+v failed.\n", faucetDbPath)
		return
	}
	faucetdb = &faucet{db: db, size: 0}
}

func main() {
	// Parse the flags and set up the logger to print everything requested
	flag.Parse()
	log.Root().SetHandler(log.LvlFilterHandler(log.Lvl(*logFlag), log.StreamHandler(os.Stderr, log.TerminalFormat(true))))

	// Load up the account key and decrypt its password
	blob, err := ioutil.ReadFile(*accPassFlag)
	if err != nil {
		log.Crit("Failed to read account password contents", "file", *accPassFlag, "err", err)
	}
	// Delete trailing newline in password
	pass := strings.TrimSuffix(string(blob), "\n")

	ks = keystore.NewKeyStore(filepath.Join(os.Getenv("HOME"), ".faucet", "keys"), keystore.StandardScryptN, keystore.StandardScryptP)
	if len(ks.Accounts()) > 0 {
		account = ks.Accounts()[0]
	} else {
		blob, err = ioutil.ReadFile(*accJSONFlag)
		if err != nil {
			log.Crit("Failed to read account key contents", "file", *accJSONFlag, "err", err)
		}
		account, err = ks.Import(blob, pass, pass)
		if err != nil {
			log.Crit("Failed to import faucet signer account", "err", err)
		}
	}
	log.Info("faucet", "chainID", chainID, "supplier", account.Address)
	if err := ks.Unlock(account, pass); err != nil {
		log.Crit("Failed to unlock account", "err", err)
	}

	if err := listenAndServe(*webPortFlag); err != nil {
		log.Crit("Failed to launch faucet API", "err", err)
	}
}

// listenAndServe registers the HTTP handlers for the faucet and boots it up
// for service user funding requests.
func listenAndServe(port int) error {
	go loopFreshDB()
	http.HandleFunc("/", webHandler)
	http.Handle("/faucet", websocket.Handler(apiHandler))
	log.Info("listenAndServe", "port", port)
	return http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

// webHandler handles all non-api requests, simply flattening and returning the
// faucet website.
func webHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("==== webHandler() ====\n")
	index := []byte("1")
	w.Write(index)
}

// apiHandler handles requests for Ether grants and transaction statuses.
func apiHandler(conn *websocket.Conn) {
	fmt.Printf("==== apiHandle() ====\n")
	// Start tracking the connection and drop at the end
	defer func() {
		conn.Close()
	}()

	//rpcserver := fmt.Sprintf("http://%v:%v", *rpcServerFlag, *rpcPortFlag)
	rpcserver := "https://rpc.smpc.network"
	log.Info("apiHandler", "rpcserver", rpcserver)

	for {
		time.Sleep(100 * time.Millisecond)
		// Gather the initial stats from the network to report
		var (
			result hexutil.Uint64
			nonce  uint64
		)
		var msg struct {
			Address  string `json:"address"`
			Cointype string `json:"cointype"`
		}
		_ = websocket.JSON.Receive(conn, &msg)
		log.Debug("faucet", "JSON.Receive", msg)
		if len(msg.Address) == 0 {
			log.Debug("faucet, address is null\n")
			send(conn, map[string]string{"state": "ERR", "msg": "Account is nil"}, time.Second)
			if errs := send(conn, map[string]interface{}{
				"state":  "ERROR",
				"funded": nonce,
			}, time.Second); errs != nil {
				log.Warn("Failed to send stats to client", "err", errs)
				conn.Close()
				break
			}
			continue
		}
		if !common.IsHexAddress(msg.Address) {
			log.Debug("faucet", "invalid address", msg.Address)
			send(conn, map[string]string{"state": "ERR", "msg": "Account is invalid"}, time.Second)
			continue
		}
		if faucetdb.size >= quotaNumber {
			log.Debug("faucet", "request coin quota is full.", "")
			send(conn, map[string]string{"state": "ERR", "msg": "Coin(CCD) request quota is nil, please try again tomorrow."}, time.Second)
			continue
		}
		ret := keyIsExist([]byte(msg.Address))
		if ret == true {
			log.Debug("faucet", "account", msg.Address, "was had requested.", "")
			send(conn, map[string]string{"state": "ERR", "msg": "The account was had requested coin(CCD)."}, time.Second)
			continue
		}
		switch msg.Cointype {
		case "CCD":
			log.Debug("faucet", "Address", msg.Address, "cointype", msg.Cointype)
			clientc, err := rpc.Dial(rpcserver)
			if err != nil {
				log.Debug("client connection error", "rpc err", err)
				continue
			}
			err = clientc.CallContext(context.Background(), &result, "eth_getTransactionCount", account.Address.String(), "pending")
			nonce = uint64(result)
			log.Debug("faucet", "nonce", nonce)
			gasLimit := uint64(100000)
			gasPrice := big.NewInt(10000000000) //10 gwei
			tx := types.NewTransaction(nonce, common.HexToAddress(msg.Address), coinNum, gasLimit, gasPrice, nil)
			signed, err := ks.SignTx(account, tx, big.NewInt(chainID))
			if err != nil {
				if err = send(conn, map[string]string{"state": "ERR", "msg": "SignTx failed."}, time.Second); err != nil {
					log.Warn("Failed to Sign transaction", "err", err)
					return
				}
				continue
			}
			// Submit the transaction and mark as funded if successful
			log.Debug("faucet", "HTTP-RPC client connected", rpcserver)
			log.Debug("Faucet", "addr", msg.Address, "coinNum", coinNum)
			client, err := ethclient.Dial(rpcserver)
			if err != nil {
				log.Debug("client connection error.", "ethclient err", err)
				continue
			}
			// Send RawTransaction to ethereum network
			err = client.SendTransaction(context.Background(), signed)
			if err != nil {
				send(conn, map[string]string{"state": "ERR", "msg": "Send Transaction Failed."}, time.Second)
				log.Debug("faucet", "client send error", err)
			} else {
				txHash := signed.Hash().String()
				send(conn, map[string]string{"state": "OK", "msg": "Send Transaction Successed.\nIt takes about 1~2 blocks (time) to get to the account.", "txhash": txHash}, time.Second)
				log.Info("faucet", "client send", "success", "txhash", txHash)
				if putKeyToDb([]byte(msg.Address)) != nil {
					log.Debug("PutKeyToDb account: %+v failed.\n", msg.Address)
				}
			}
		default:
			log.Warn("faucet", "unkown cointype", msg.Cointype)
		}
	}
}

// sends transmits a data packet to the remote end of the websocket, but also
// setting a write deadline to prevent waiting forever on the node.
func send(conn *websocket.Conn, value interface{}, timeout time.Duration) error {
	log.Debug("faucet", "send, value", value)
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	conn.SetWriteDeadline(time.Now().Add(timeout))
	return websocket.JSON.Send(conn, value)
}

func loopFreshDB() {
	log.Debug("==== loop() ====\n")
	refreshDone = nil
	dbTime = getDbDate()

	for {
		select {
		case <-refresh.C:
			refreshDb()
		case <-refreshDone:
			faucetdb.db.Close()
			break
		}
	}
}

func refreshDb() {
	if dbTime == "" {
		return
	}
	at := fmt.Sprintf("%+v", time.Now())
	n := strings.Split(at, " ")
	if dbTime != string(n[0]) {
		dbTime = string(n[0])
		emptyDb()
	}
}

func emptyDb() {
	log.Debug("==== emptyDb() ====\n")
	iter := faucetdb.db.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		faucetdb.db.Delete(iter.Key(), nil)
	}
	faucetdb.size = 0
}

func getDbDate() string {
	log.Debug("==== getDbDate() ====\n")
	iter := faucetdb.db.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		d := strings.Split(string(iter.Value()), " ")
		return string(d[0])
	}
	return ""
}

func keyIsExist(key []byte) bool {
	_, err := faucetdb.db.Get(key, nil)
	if err != nil {
		return false
	}
	return true
}

func putKeyToDb(key []byte) error {
	at := fmt.Sprintf("%+v", time.Now())
	err := faucetdb.db.Put(key, []byte(at), nil)
	if err != nil {
		log.Debug("putKeyToDb", "put, key", key, "faied", "")
		return err
	}
	faucetdb.size += 1
	log.Debug("putKeyToDb", "size", faucetdb.size, "quotaNumber", quotaNumber, "remain", quotaNumber-faucetdb.size)
	return nil
}
