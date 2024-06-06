package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	ethtxman "github.com/0xPolygonHermez/zkevm-ethtx-manager/etherman"
	sstypes "github.com/0xPolygonHermez/zkevm-sequence-sender/config/types"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/etherman"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/log"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/sequencesender"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"
)

const SEND_TX_L1 = false

type ParamsItem struct {
	From                string   `json:"from"`
	To                  string   `json:"to"`
	Data                string   `json:"data"`
	BlobVersionedHashes []string `json:"blobVersionedHashes,omitempty"`
}

type JsonRequest struct {
	Jsonrpc string       `json:"jsonrpc"`
	Method  string       `json:"method"`
	Params  []ParamsItem `json:"params"`
	Id      int          `json:"id"`
}

type SidecarData struct {
	Commit string `json:"commitment"`
	Proof  string `json:"proof"`
	Blob   string `json:"blob"`
}

func main() {
	// Config
	cfgSS := sequencesender.Config{
		L2Coinbase: common.HexToAddress("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
		PrivateKey: sstypes.KeystoreFileConfig{
			Path:     "sequencer.keystore",
			Password: "testonly",
		},
	}

	cfg := etherman.Config{
		EthermanConfig: ethtxman.Config{
			URL:              "http://127.0.0.1:8545",
			MultiGasProvider: false,
			L1ChainID:        1337,
		},
	}

	cfgL1 := etherman.L1Config{
		L1ChainID:                 1337,
		ZkEVMAddr:                 common.HexToAddress("0x8dAF17A20c9DBA35f005b6324F493785D239719d"),
		RollupManagerAddr:         common.HexToAddress("0xB7f8BC63BbcaD18155201308C8f3540b07f84F5e"),
		PolAddr:                   common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3"),
		GlobalExitRootManagerAddr: common.HexToAddress("0x8A791620dd6260079BF849Dc5567aDC3F2FdC318"),
	}

	// Etherman
	ethClient, err := etherman.NewClient(cfg, cfgL1)
	if err != nil {
		log.Errorf("error creating etherman client: %v", err)
		return
	}
	_, err = ethClient.LoadAuthFromKeyStore(cfgSS.PrivateKey.Path, cfgSS.PrivateKey.Password)
	if err != nil {
		log.Errorf("error loading private key: %v", err)
		return
	}

	// Current nonce
	ctx := context.Background()
	currentNonce, err := ethClient.CurrentNonce(ctx, cfgSS.L2Coinbase)
	if err != nil {
		log.Errorf("error getting current nonce: %v", err)
		return
	} else {
		log.Infof("current nonce for %v is %d", cfgSS.L2Coinbase, currentNonce)
	}

	// Load tx data
	file, err := os.Open("txdata.json")
	if err != nil {
		log.Errorf("error opening json file with tx data: %v", err)
		return
	}
	defer file.Close()

	// Decode tx data
	var request JsonRequest
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&request); err != nil {
		log.Errorf("error decoding json file with tx data: %v", err)
		return
	}

	var sidecarJson SidecarData
	if request.Params[0].BlobVersionedHashes != nil {
		// Load tx sidecar
		file2, err := os.Open("txsidecar.json")
		if err != nil {
			log.Errorf("error opening json file with tx sidecar: %v", err)
			return
		}
		defer file2.Close()

		decoder := json.NewDecoder(file2)
		if err := decoder.Decode(&sidecarJson); err != nil {
			log.Errorf("error decoding json file with tx sidecar: %v", err)
			return
		}
	}

	data, err := hex.DecodeString(request.Params[0].Data[2:])
	if err != nil {
		log.Errorf("error decoding data: %v", err)
		return
	}
	from := common.HexToAddress(request.Params[0].From)
	to := common.HexToAddress(request.Params[0].To)
	log.Infof("loaded length data: %d", len(data))
	log.Infof("loaded from: %s", from)
	log.Infof("loaded to: %s", to)

	var sidecar *types.BlobTxSidecar
	if request.Params[0].BlobVersionedHashes != nil {
		commit0, _ := hex.DecodeString(sidecarJson.Commit[2:])
		proof0, _ := hex.DecodeString(sidecarJson.Proof[2:])
		blob0, _ := hex.DecodeString(sidecarJson.Blob[2:])

		sidecar = &types.BlobTxSidecar{
			Commitments: []kzg4844.Commitment{
				kzg4844.Commitment(commit0),
			},
			Proofs: []kzg4844.Proof{
				kzg4844.Proof(proof0),
			},
			Blobs: []kzg4844.Blob{
				kzg4844.Blob(blob0),
			},
		}
	}

	// Send tx
	id, err := sendTx(ethClient, ctx, from, &to, &currentNonce, big.NewInt(0), data, sidecar)
	if err != nil {
		log.Errorf("error: %v", err)
		return
	} else {
		log.Infof("tx sent %v", id)
	}
}

func sendTx(c *etherman.Client, ctx context.Context, from common.Address, to *common.Address, forcedNonce *uint64, value *big.Int, data []byte, sidecar *types.BlobTxSidecar) (common.Hash, error) {
	// Info
	log.Infof("from: %s", from.Hex())
	log.Infof("to: %v", *to)
	log.Infof("value: %d", value.Uint64())
	log.Infof("length data: %d", len(data))
	if sidecar != nil {
		if len(sidecar.Blobs) > 0 {
			log.Infof("length blob0: %d", len(sidecar.Blobs[0]))
			log.Infof("length commitments0: %d", len(sidecar.Commitments[0]))
			log.Infof("length proofs0: %d", len(sidecar.Proofs[0]))
		}
	}

	// Nonce
	var nonce uint64
	var err error
	if forcedNonce == nil {
		// get next nonce
		nonce, err = c.CurrentNonce(ctx, from)
		if err != nil {
			err := fmt.Errorf("failed to get current nonce: %w", err)
			log.Errorf(err.Error())
			return common.Hash{}, err
		} else {
			log.Infof("current nonce for %v is %d", from, nonce)
		}
	} else {
		nonce = *forcedNonce
	}

	// Gas price
	gasPrice, err := c.EthClient.SuggestGasPrice(ctx)
	if err != nil {
		err := fmt.Errorf("failed to get suggested gas price: %w", err)
		log.Errorf(err.Error())
		return common.Hash{}, err
	} else {
		log.Infof("suggested gas price is %d", gasPrice.Uint64())
	}

	var gas uint64
	var blobFeeCap *big.Int
	var gasTipCap *big.Int

	if sidecar != nil {
		log.Infof("**** BLOB TX ****")

		// blob gas price estimation
		parentHeader, err := c.EthClient.HeaderByNumber(ctx, nil)
		if err != nil {
			log.Errorf("failed to get parent header: %v", err)
			return common.Hash{}, err
		} else {
			log.Infof("parent header: %+v", parentHeader)
		}

		if parentHeader.ExcessBlobGas != nil && parentHeader.BlobGasUsed != nil {
			parentExcessBlobGas := eip4844.CalcExcessBlobGas(*parentHeader.ExcessBlobGas, *parentHeader.BlobGasUsed)
			blobFeeCap = eip4844.CalcBlobFee(parentExcessBlobGas)
		} else {
			log.Infof("legacy parent header no blob gas info")
			blobFeeCap = eip4844.CalcBlobFee(0)
		}
		log.Infof("blob fee cap is %d", blobFeeCap.Uint64())

		gasTipCap, err = c.EthClient.SuggestGasTipCap(ctx)
		if err != nil {
			log.Errorf("failed to get gas tip cap: %v", err)
			return common.Hash{}, err
		}
		log.Infof("suggested gas tip cap is %d", gasTipCap.Uint64())

		// get gas
		gas0, err0 := estimateGas(c, ctx, from, to, value, data)
		if err0 != nil {
			if de, ok := err0.(rpc.DataError); ok {
				err0 = fmt.Errorf("%w (%v)", err0, de.ErrorData())
			}
			log.Infof("estimateGas error: %v", err0)
		} else {
			log.Infof("gas: %d", gas0)
		}

		gas, err = estimateGasBlobTx(c, ctx, from, to, gasPrice, gasTipCap, value, data)
		if err != nil {
			if de, ok := err.(rpc.DataError); ok {
				err = fmt.Errorf("%w (%v)", err, de.ErrorData())
			}
			log.Errorf("estimateGasBlobTx error: %v (from %s to %s value %s)", err, from.String(), to.String(), value.String())
			gas = 1000000
			log.Infof("A default gas will be used: %d", gas)
		} else {
			log.Infof("estimate gas is %d", gas)
		}

		// margin
		const multiplier = 10
		gasTipCap = gasTipCap.Mul(gasTipCap, big.NewInt(multiplier))
		gasPrice = gasPrice.Mul(gasPrice, big.NewInt(multiplier))
		blobFeeCap = blobFeeCap.Mul(blobFeeCap, big.NewInt(multiplier))
		gas = gas * 12 / 10 //nolint:gomnd
	} else {
		log.Infof("**** LEGACY TX ****")

		// get gas
		gas, err = estimateGas(c, ctx, from, to, value, data)
		if err != nil {
			if de, ok := err.(rpc.DataError); ok {
				err = fmt.Errorf("%w (%v)", err, de.ErrorData())
			}
			log.Errorf("estimateGas error: %v (from %s to %s value %s)", err, from.String(), to.String(), value.String())
			gas = 1000000
			log.Infof("A default gas will be used: %d", gas)
		} else {
			log.Infof("estimate gas is %d", gas)
		}
	}

	// Create tx
	var tx *types.Transaction
	if sidecar == nil {
		tx = types.NewTx(&types.LegacyTx{
			To:       to,
			Nonce:    nonce,
			Value:    value,
			Data:     data,
			Gas:      gas,
			GasPrice: gasPrice,
		})
	} else {
		tx = types.NewTx(&types.BlobTx{
			To:         *to,
			Nonce:      nonce,
			Value:      uint256.MustFromBig(value),
			Data:       data,
			GasFeeCap:  uint256.MustFromBig(gasPrice),
			GasTipCap:  uint256.MustFromBig(gasTipCap),
			Gas:        gas,
			BlobFeeCap: uint256.MustFromBig(blobFeeCap),
			BlobHashes: sidecar.BlobHashes(),
			Sidecar:    sidecar,
		})
	}

	// Sign tx
	opts, err := c.GetAuthByAddress(from)
	if err != nil {
		log.Errorf("error getting private key: %v", err)
		return common.Hash{}, err
	}
	if opts.Signer == nil {
		log.Errorf("error no signer to authorize the transaction")
		return common.Hash{}, err
	}
	signedTx, err := opts.Signer(opts.From, tx)
	if err != nil {
		log.Errorf("error signing tx: %v", err)
		return common.Hash{}, err
	}
	log.Infof("signed tx %v created", signedTx.Hash().String())

	// Send to network
	if SEND_TX_L1 {
		err = c.EthClient.SendTransaction(ctx, signedTx)
		if err != nil {
			log.Errorf("error sending tx %v: %v", signedTx.Hash().String(), err)
			return common.Hash{}, err
		}
		log.Infof("tx sent to the network")
	} else {
		log.Infof("complete! tx sending to the network is DISABLE")
	}

	return signedTx.Hash(), nil
}

func estimateGas(c *etherman.Client, ctx context.Context, from common.Address, to *common.Address, value *big.Int, data []byte) (uint64, error) {
	return c.EthClient.EstimateGas(ctx, ethereum.CallMsg{
		From:  from,
		To:    to,
		Value: value,
		Data:  data,
	})
}

func estimateGasBlobTx(c *etherman.Client, ctx context.Context, from common.Address, to *common.Address, gasFeeCap *big.Int, gasTipCap *big.Int, value *big.Int, data []byte) (uint64, error) {
	return c.EthClient.EstimateGas(ctx, ethereum.CallMsg{
		From:      from,
		To:        to,
		GasFeeCap: gasFeeCap,
		GasTipCap: gasTipCap,
		Value:     value,
		Data:      data,
	})
}
