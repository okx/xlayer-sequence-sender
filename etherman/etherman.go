package etherman

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/0xPolygonHermez/zkevm-sequence-sender/etherman/smartcontracts/polygonrollupmanager"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/etherman/smartcontracts/polygonzkevmfeijoa"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/etherman/smartcontracts/polygonzkevmglobalexitrootv2"
	ethmanTypes "github.com/0xPolygonHermez/zkevm-sequence-sender/etherman/types"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/log"
	"github.com/0xPolygonHermez/zkevm-sequence-sender/state"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"github.com/iden3/go-iden3-crypto/keccak256"
)

const (
	// BLOB_TX_TYPE is a blob transaction type
	BLOB_TX_TYPE = byte(0x03)
)

var (
	// ErrBlobOversizedData when blob data is longer than allowed
	ErrBlobOversizedData = errors.New("blob data longer than allowed")
	// ErrL1InfoLeafIndexLowerThanPrevious when l1 info tree index is lower than previous one within a blob data
	ErrL1InfoLeafIndexLowerThanPrevious = errors.New("l1 info tree index value lower than previous value")
)

const (
	blobTypeDataTx = 0
	blobTypeBlobTx = 1
	blobTypeForced = 2

	blobCompressionNone      = 0x00
	blobCompressionStateless = 0x01
	blobCompressionFull      = 0x02

	gasLimitPerBatch = uint64(100000000)
)

type ethereumClient interface {
	ethereum.ChainReader
	ethereum.ChainStateReader
	ethereum.ContractCaller
	ethereum.GasEstimator
	ethereum.GasPricer
	ethereum.GasPricer1559
	ethereum.LogFilterer
	ethereum.TransactionReader
	ethereum.TransactionSender

	bind.DeployBackend
}

// L1Config represents the configuration of the network used in L1
type L1Config struct {
	// Chain ID of the L1 network
	L1ChainID uint64 `json:"chainId"`
	// ZkEVMAddr Address of the L1 contract polygonZkEVMAddress
	ZkEVMAddr common.Address `json:"polygonZkEVMAddress"`
	// RollupManagerAddr Address of the L1 contract
	RollupManagerAddr common.Address `json:"polygonRollupManagerAddress"`
	// PolAddr Address of the L1 Pol token Contract
	PolAddr common.Address `json:"polTokenAddress"`
	// GlobalExitRootManagerAddr Address of the L1 GlobalExitRootManager contract
	GlobalExitRootManagerAddr common.Address `json:"polygonZkEVMGlobalExitRootAddress"`
}

// Client is a simple implementation of EtherMan.
type Client struct {
	EthClient      ethereumClient
	ZkEVM          *polygonzkevmfeijoa.Polygonzkevmfeijoa
	RollupManager  *polygonrollupmanager.Polygonrollupmanager
	GlobalExitRoot *polygonzkevmglobalexitrootv2.Polygonzkevmglobalexitrootv2

	RollupID uint32

	l1Cfg L1Config
	cfg   Config
	auth  map[common.Address]bind.TransactOpts // empty in case of read-only client
}

type sequenceBlobData struct {
	maxSequenceTimestamp uint64
	zkGasLimit           uint64
	l1InfoLeafIndex      uint32
	blobData             []byte
}

// NewClient creates a new etherman.
func NewClient(cfg Config, l1Config L1Config) (*Client, error) {
	// Connect to ethereum node
	ethClient, err := ethclient.Dial(cfg.EthermanConfig.URL)
	if err != nil {
		log.Errorf("error connecting to %s: %+v", cfg.EthermanConfig.URL, err)
		return nil, err
	}
	// Create SC clients
	zkevm, err := polygonzkevmfeijoa.NewPolygonzkevmfeijoa(l1Config.ZkEVMAddr, ethClient)
	if err != nil {
		return nil, err
	}
	rollupManager, err := polygonrollupmanager.NewPolygonrollupmanager(l1Config.RollupManagerAddr, ethClient)
	if err != nil {
		return nil, err
	}
	globalExitRoot, err := polygonzkevmglobalexitrootv2.NewPolygonzkevmglobalexitrootv2(l1Config.GlobalExitRootManagerAddr, ethClient)
	if err != nil {
		return nil, err
	}

	// Get RollupID
	rollupID, err := rollupManager.RollupAddressToID(&bind.CallOpts{Pending: false}, l1Config.ZkEVMAddr)
	if err != nil {
		return nil, err
	}
	log.Debug("rollupID: ", rollupID)

	return &Client{
		EthClient:      ethClient,
		ZkEVM:          zkevm,
		RollupManager:  rollupManager,
		GlobalExitRoot: globalExitRoot,
		RollupID:       rollupID,
		l1Cfg:          l1Config,
		cfg:            cfg,
		auth:           map[common.Address]bind.TransactOpts{},
	}, nil
}

// EstimateGasSequenceBatches estimates gas for sending batches
func (etherMan *Client) EstimateGasSequenceBatches(sender common.Address, sequences []ethmanTypes.Sequence, l2Coinbase common.Address, oldAccInputHash common.Hash) (*types.Transaction, error) {
	const GWEI_DIV = 1000000000

	opts, err := etherMan.GetAuthByAddress(sender)
	if err == ErrNotFound {
		return nil, ErrPrivateKeyNotFound
	}
	opts.NoSend = true

	var firstSeq, lastSeq uint64
	if len(sequences) > 0 {
		firstSeq = sequences[0].BatchNumber
		lastSeq = sequences[len(sequences)-1].BatchNumber
	}

	// Cost using calldata tx
	tx, _, err := etherMan.sequenceBatchesData(opts, sequences, l2Coinbase, oldAccInputHash)
	if err != nil {
		return nil, err
	}

	estimateDataCost := new(big.Int).Mul(tx.GasPrice(), new(big.Int).SetUint64(tx.Gas())).Uint64()
	log.Infof("(%d-%d) >> tx DATA cost: %9d Gwei = %d gas x %d gasPrice", firstSeq, lastSeq, estimateDataCost/GWEI_DIV, tx.Gas(), tx.GasPrice().Uint64())

	// Cost using blob tx
	opts.GasFeeCap = big.NewInt(1)
	opts.GasTipCap = big.NewInt(1)
	blobTx, _, err := etherMan.sequenceBatchesBlob(opts, sequences, l2Coinbase, oldAccInputHash)
	if err != nil {
		return nil, err
	}

	estimateBlobCost := new(big.Int).Mul(blobTx.BlobGasFeeCap(), new(big.Int).SetUint64(blobTx.BlobGas())).Uint64()
	log.Infof("(%d-%d) >> tx BLOB cost: %9d Gwei = %d blobGas x %d blobGasPrice", firstSeq, lastSeq, estimateBlobCost/GWEI_DIV, blobTx.BlobGas(), blobTx.BlobGasFeeCap().Uint64())

	// Return the cheapest one
	if estimateBlobCost*10000000 < estimateDataCost {
		return blobTx, nil
	} else {
		return tx, nil
	}
}

// BuildSequenceBatchesTxData builds a []bytes to be sent as calldata to the SC method SequenceBatches
func (etherMan *Client) BuildSequenceBatchesTxData(sender common.Address, sequences []ethmanTypes.Sequence, l2Coinbase common.Address, oldAccInputHash common.Hash) (to *common.Address, data []byte, newAccInputHash common.Hash, err error) {
	opts, err := etherMan.GetAuthByAddress(sender)
	if err == ErrNotFound {
		return nil, nil, common.Hash{}, fmt.Errorf("failed to build sequence batches: %w", ErrPrivateKeyNotFound)
	}
	opts.NoSend = true
	// force nonce, gas limit and gas price to avoid querying it from the chain
	opts.Nonce = big.NewInt(1)
	opts.GasLimit = uint64(1)
	opts.GasPrice = big.NewInt(1)

	var tx *types.Transaction
	tx, newAccInputHash, err = etherMan.sequenceBatchesData(opts, sequences, l2Coinbase, oldAccInputHash)
	if err != nil {
		return nil, nil, common.Hash{}, err
	}

	return tx.To(), tx.Data(), newAccInputHash, nil
}

// BuildSequenceBatchesTxBlob builds a types.BlobTxSidecar to be sent as blobs to the SC method SequenceBatchesBlob
func (etherMan *Client) BuildSequenceBatchesTxBlob(sender common.Address, sequences []ethmanTypes.Sequence, l2Coinbase common.Address, oldAccInputHash common.Hash) (to *common.Address, data []byte, sidecar *types.BlobTxSidecar, newAccInputHash common.Hash, err error) {
	opts, err := etherMan.GetAuthByAddress(sender)
	if err == ErrNotFound {
		return nil, nil, nil, common.Hash{}, fmt.Errorf("failed to build sequence batches: %w", ErrPrivateKeyNotFound)
	}
	opts.NoSend = true
	// force nonce, gas limit and gas price to avoid querying it from the chain
	opts.Nonce = big.NewInt(1)
	opts.GasLimit = uint64(1)
	opts.GasPrice = big.NewInt(1)
	opts.GasFeeCap = big.NewInt(1)
	opts.GasTipCap = big.NewInt(1)

	var tx *types.Transaction
	tx, newAccInputHash, err = etherMan.sequenceBatchesBlob(opts, sequences, l2Coinbase, oldAccInputHash)
	if err != nil {
		return nil, nil, nil, common.Hash{}, err
	}

	return tx.To(), tx.Data(), tx.BlobTxSidecar(), newAccInputHash, nil
}

// prepareBlobData prepares the sequence information to be sent as a blob data
func (etherMan *Client) prepareBlobData(sequences []ethmanTypes.Sequence) (*sequenceBlobData, error) {
	var blobBody []byte
	seqBlobData := &sequenceBlobData{}

	for _, seq := range sequences {
		// Sanity check
		if seq.L1InfoTreeIndex > 0 && seq.L1InfoTreeIndex < seqBlobData.l1InfoLeafIndex {
			return nil, ErrL1InfoLeafIndexLowerThanPrevious
		}
		// Update global blob data params
		seqBlobData.maxSequenceTimestamp = uint64(seq.LastL2BLockTimestamp)
		seqBlobData.l1InfoLeafIndex = seq.L1InfoTreeIndex
		seqBlobData.zkGasLimit = seqBlobData.zkGasLimit + gasLimitPerBatch

		// Batch data encoding
		var batchData []byte
		batchData = append(batchData, state.EncodeUint32(uint32(len(seq.BatchL2Data)))...)
		batchData = append(batchData, seq.BatchL2Data...)

		// Add batch to the blob body data
		blobBody = append(blobBody, batchData...)
	}

	// Blob data = Blob header (compression type and blob body length) + Blob body
	seqBlobData.blobData = make([]byte, 1)
	seqBlobData.blobData[0] = blobCompressionNone
	seqBlobData.blobData = append(seqBlobData.blobData, state.EncodeUint32(uint32(len(blobBody)))...)
	seqBlobData.blobData = append(seqBlobData.blobData, blobBody...)

	return seqBlobData, nil
}

// sequenceBatchesData generates an Ethereum transaction of type calldata for sending the blob data sequence
func (etherMan *Client) sequenceBatchesData(opts bind.TransactOpts, sequences []ethmanTypes.Sequence, l2Coinbase common.Address, oldAccInputHash common.Hash) (*types.Transaction, common.Hash, error) {
	// Prepare the batch sequence info
	seqBlobData, err := etherMan.prepareBlobData(sequences)
	if err != nil {
		return nil, common.Hash{}, err
	}

	// Prepare blob params using ABI encoder
	uint64Ty, _ := abi.NewType("uint64", "", nil)
	uint32Ty, _ := abi.NewType("uint32", "", nil)
	bytesTy, _ := abi.NewType("bytes", "", nil)
	arguments := abi.Arguments{
		{Type: uint64Ty},
		{Type: uint64Ty},
		{Type: uint32Ty},
		{Type: bytesTy},
	}
	blobParams, err := arguments.Pack(seqBlobData.maxSequenceTimestamp, seqBlobData.zkGasLimit, seqBlobData.l1InfoLeafIndex, seqBlobData.blobData)
	if err != nil {
		log.Errorf("error packing arguments: %v", err)
		return nil, common.Hash{}, err
	}

	blobData := []polygonzkevmfeijoa.PolygonRollupBaseFeijoaBlobData{
		{
			BlobType:       blobTypeDataTx,
			BlobTypeParams: blobParams,
		},
	}

	// Get lastL1InfoTreeRoot (if index==0 then root=0, no call is needed)
	var lastL1InfoTreeRoot common.Hash
	if seqBlobData.l1InfoLeafIndex > 0 {
		lastL1InfoTreeRoot, err = etherMan.GlobalExitRoot.L1InfoLeafMap(&bind.CallOpts{Pending: false}, big.NewInt(int64(seqBlobData.l1InfoLeafIndex)))
		if err != nil {
			log.Errorf("error calling SC globalexitroot L1InfoLeafMap: %v", err)
			return nil, common.Hash{}, err
		}
	}

	// Calculate the accumulated input hash
	newAccInputHash := calculateAccInputHash(oldAccInputHash, seqBlobData.l1InfoLeafIndex, lastL1InfoTreeRoot, seqBlobData.maxSequenceTimestamp, l2Coinbase,
		seqBlobData.zkGasLimit, blobTypeDataTx, [32]byte{}, [32]byte{}, seqBlobData.blobData, common.Hash{})

	// SC call
	tx, err := etherMan.ZkEVM.SequenceBlobs(&opts, blobData, l2Coinbase, newAccInputHash)
	etherMan.dumpCurlCallTx(opts, *tx, false, true)
	if err != nil {
		etherMan.dumpCurlCall(&opts, l2Coinbase, seqBlobData, &blobData, newAccInputHash, []common.Hash{}, false)
		if parsedErr, ok := tryParseError(err); ok {
			err = parsedErr
		}
	}

	return tx, newAccInputHash, err
}

// sequenceBatchesBlob generates an Ethereum transaction of type blob for sending the blob data sequence
func (etherMan *Client) sequenceBatchesBlob(opts bind.TransactOpts, sequences []ethmanTypes.Sequence, l2Coinbase common.Address, oldAccInputHash common.Hash) (*types.Transaction, common.Hash, error) {
	// Prepare the batch sequence info
	seqBlobData, err := etherMan.prepareBlobData(sequences)
	if err != nil {
		return nil, common.Hash{}, err
	}

	// Construct blob tx data
	blob, err := encodeBlobData(seqBlobData.blobData)
	if err != nil {
		log.Errorf("error encoding blob: %v", err)
		return nil, common.Hash{}, err
	}
	sidecar := makeBlobSidecar([]kzg4844.Blob{blob})
	blobHashes := sidecar.BlobHashes()

	// Calculate params
	var blobIndex [32]byte
	var pointZ [32]byte
	var pointY [32]byte
	var blobCommitmentProof []byte
	if len(sidecar.Commitments) > 0 {
		blobCommitmentProof = append([]byte{}, sidecar.Commitments[0][:]...)
		blobCommitmentProof = append(blobCommitmentProof, sidecar.Proofs[0][:]...)
	}

	// Prepare blob params using ABI encoder
	uint64Ty, _ := abi.NewType("uint64", "", nil)
	uint32Ty, _ := abi.NewType("uint32", "", nil)
	bytes32Ty, _ := abi.NewType("bytes32", "", nil)
	bytesTy, _ := abi.NewType("bytes", "", nil)
	arguments := abi.Arguments{
		{Type: uint64Ty},
		{Type: uint64Ty},
		{Type: uint32Ty},
		{Type: bytes32Ty},
		{Type: bytes32Ty},
		{Type: bytes32Ty},
		{Type: bytesTy},
	}
	blobParams, err := arguments.Pack(
		seqBlobData.maxSequenceTimestamp,
		seqBlobData.zkGasLimit,
		seqBlobData.l1InfoLeafIndex,
		blobIndex,
		pointZ,
		pointY,
		blobCommitmentProof)
	if err != nil {
		log.Errorf("error packing arguments: %v", err)
		return nil, common.Hash{}, err
	}

	blobData := []polygonzkevmfeijoa.PolygonRollupBaseFeijoaBlobData{
		{
			BlobType:       blobTypeBlobTx,
			BlobTypeParams: blobParams,
		},
	}

	// Get lastL1InfoTreeRoot (if index==0 then root=0, no call is needed)
	var lastL1InfoTreeRoot common.Hash
	if seqBlobData.l1InfoLeafIndex > 0 {
		lastL1InfoTreeRoot, err = etherMan.GlobalExitRoot.L1InfoLeafMap(&bind.CallOpts{Pending: false}, big.NewInt(int64(seqBlobData.l1InfoLeafIndex)))
		if err != nil {
			log.Errorf("error calling SC globalexitroot L1InfoLeafMap: %v", err)
			return nil, common.Hash{}, err
		}
	}

	// Calculate the accumulated input hash
	newAccInputHash := calculateAccInputHash(oldAccInputHash, seqBlobData.l1InfoLeafIndex, lastL1InfoTreeRoot, seqBlobData.maxSequenceTimestamp, l2Coinbase,
		seqBlobData.zkGasLimit, blobTypeBlobTx, [32]byte{}, [32]byte{}, []byte{}, common.Hash{})

	// Max Gas
	parentHeader, err := etherMan.EthClient.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Errorf("failed to get header from previous block: %v", err)
		return nil, common.Hash{}, err
	}
	parentExcessBlobGas := eip4844.CalcExcessBlobGas(*parentHeader.ExcessBlobGas, *parentHeader.BlobGasUsed)
	blobFeeCap := eip4844.CalcBlobFee(parentExcessBlobGas)

	// Prepare data using ABI encoder
	abiFeijoa, err := polygonzkevmfeijoa.PolygonzkevmfeijoaMetaData.GetAbi()
	if err != nil {
		log.Errorf("error parsing JSON: %v", err)
		return nil, common.Hash{}, err
	}
	inputParams, err := abiFeijoa.Pack("sequenceBlobs", blobData, l2Coinbase, newAccInputHash)
	if err != nil {
		log.Errorf("error packing arguments: %v", err)
		return nil, common.Hash{}, err
	}

	// Transaction
	blobTx := types.NewTx(&types.BlobTx{
		To:         etherMan.l1Cfg.ZkEVMAddr,
		GasTipCap:  uint256.MustFromBig(opts.GasTipCap),
		GasFeeCap:  uint256.MustFromBig(opts.GasFeeCap),
		BlobFeeCap: uint256.MustFromBig(blobFeeCap),
		BlobHashes: blobHashes,
		Data:       inputParams,
		Sidecar:    sidecar,
	})

	signedTx, err := opts.Signer(opts.From, blobTx)
	etherMan.dumpCurlCallTx(opts, *blobTx, false, true)
	if err != nil {
		// etherMan.dumpCurlCall(&opts, l2Coinbase, seqBlobData, &blobData, newAccInputHash, blobHashes, false)
		return nil, common.Hash{}, err
	}

	return signedTx, newAccInputHash, err
}

// AddOrReplaceAuth adds an authorization or replace an existent one to the same account
func (etherMan *Client) AddOrReplaceAuth(auth bind.TransactOpts) error {
	log.Infof("added or replaced authorization for address: %v", auth.From.String())
	etherMan.auth[auth.From] = auth
	return nil
}

// NewAuthFromKeystore an authorization instance from a keystore file
func (etherMan *Client) NewAuthFromKeystore(path, password string, chainID uint64) (bind.TransactOpts, error) {
	log.Infof("reading key from: %v", path)
	key, err := newKeyFromKeystore(path, password)
	if err != nil {
		return bind.TransactOpts{}, err
	}
	if key == nil {
		return bind.TransactOpts{}, nil
	}
	auth, err := bind.NewKeyedTransactorWithChainID(key.PrivateKey, new(big.Int).SetUint64(chainID))
	if err != nil {
		return bind.TransactOpts{}, err
	}
	return *auth, nil
}

// newKeyFromKeystore creates an instance of a keystore key from a keystore file
func newKeyFromKeystore(path, password string) (*keystore.Key, error) {
	if path == "" && password == "" {
		return nil, nil
	}
	keystoreEncrypted, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	log.Infof("decrypting key from: %v", path)
	key, err := keystore.DecryptKey(keystoreEncrypted, password)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// SendTx sends a tx to L1
func (etherMan *Client) SendTx(ctx context.Context, tx *types.Transaction) error {
	return etherMan.EthClient.SendTransaction(ctx, tx)
}

// CurrentNonce returns the current nonce for the provided account
func (etherMan *Client) CurrentNonce(ctx context.Context, account common.Address) (uint64, error) {
	return etherMan.EthClient.NonceAt(ctx, account, nil)
}

// LoadAuthFromKeyStore loads an authorization from a key store file
func (etherMan *Client) LoadAuthFromKeyStore(path, password string) (*bind.TransactOpts, error) {
	auth, err := etherMan.NewAuthFromKeystore(path, password, etherMan.l1Cfg.L1ChainID)
	if err != nil {
		return nil, err
	}

	log.Infof("loaded authorization for address: %v", auth.From.String())
	etherMan.auth[auth.From] = auth
	return &auth, nil
}

// GetAuthByAddress tries to get an authorization from the authorizations map
func (etherMan *Client) GetAuthByAddress(addr common.Address) (bind.TransactOpts, error) {
	auth, found := etherMan.auth[addr]
	if !found {
		return bind.TransactOpts{}, ErrNotFound
	}
	return auth, nil
}

// LastAccInputHash gets the last acc input hash from the SC
func (etherMan *Client) LastAccInputHash() (common.Hash, error) {
	return etherMan.ZkEVM.LastAccInputHash(&bind.CallOpts{Pending: false})
}

// dumpCurlCall dumps log info to make the curl call from the command line
func (etherMan *Client) dumpCurlCall(opts *bind.TransactOpts, l2Coinbase common.Address, seqBlobData *sequenceBlobData,
	blobData *[]polygonzkevmfeijoa.PolygonRollupBaseFeijoaBlobData, accInputHash common.Hash, blobHashes []common.Hash, dumpScreen bool) {
	if dumpScreen {
		// Log info
		log.Infof("l2CoinBase: %v", l2Coinbase)
		log.Infof("sequencer: %v", opts.From)
		log.Infof("accInputHash: %v", accInputHash)
		log.Infof("seq.maxSequenceTimestamp: %v", seqBlobData.maxSequenceTimestamp)
		log.Infof("seq.zkGasLimit: %v", seqBlobData.zkGasLimit)
		log.Infof("seq.l1InfoLeafIndex: %v", seqBlobData.l1InfoLeafIndex)
		var isBlobTx bool
		if len(*blobData) > 0 {
			isBlobTx = (*blobData)[0].BlobType == blobTypeBlobTx
			log.Infof("BlobType: %v", (*blobData)[0].BlobType)
			log.Infof("BlobTypeParams (length %d)", len((*blobData)[0].BlobTypeParams))
		} else {
			isBlobTx = false
			log.Infof("Empty blobData!")
		}

		abiFeijoa, err := polygonzkevmfeijoa.PolygonzkevmfeijoaMetaData.GetAbi()
		if err != nil {
			log.Errorf("error parsing JSON: %v", err)
			return
		}
		inputParams, err := abiFeijoa.Pack("sequenceBlobs", blobData, l2Coinbase, accInputHash)
		if err != nil {
			log.Errorf("error packing arguments: %v", err)
			return
		}
		log.Infof("inputData (length %d)", len(inputParams))

		ctx := context.Background()
		block, err := etherMan.EthClient.BlockByNumber(ctx, nil)
		var blockStr string
		if err != nil {
			log.Errorf("error getting blockNumber: %v", err)
			blockStr = "latest"
		} else {
			blockStr = fmt.Sprintf("0x%x", block.Number())
		}

		if !isBlobTx {
			log.Infof(`Use the next command to debug it manually.
			curl --location --request POST 'http://localhost:8545' \
			--header 'Content-Type: application/json' \
			--data-raw '{
				"jsonrpc": "2.0",
				"method": "eth_call",
				"params": [{"from": "%s","to":"%s","data":"0x%s"},"%s"],
				"id": 1
			}'`, opts.From, etherMan.l1Cfg.ZkEVMAddr, common.Bytes2Hex(inputParams), blockStr)
		} else {
			var blobHash common.Hash
			if len(blobHashes) > 0 {
				blobHash = blobHashes[0]
			}
			log.Infof(`Use the next command to debug it manually.
			curl --location --request POST 'http://localhost:8545' \
			--header 'Content-Type: application/json' \
			--data-raw '{
				"jsonrpc": "2.0",
				"method": "eth_call",
				"params": [{"from": "%s","to":"%s","data":"0x%s", "blobVersionedHashes":["%s"]},"%s"],
				"id": 1
			}'`, opts.From, etherMan.l1Cfg.ZkEVMAddr, common.Bytes2Hex(inputParams), blobHash, blockStr)
		}
	}
}

// dumpCurlCallTx dumps log info to make the curl call from the command line
func (etherMan *Client) dumpCurlCallTx(opts bind.TransactOpts, tx types.Transaction, dumpScreen bool, dumpFile bool) {
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

	var blobHash0 string
	var commit0 string
	var proofs0 string
	var blob0 string
	blobType := tx.Type() == BLOB_TX_TYPE
	if blobType {
		sidecar := tx.BlobTxSidecar()
		if len(sidecar.Blobs) > 0 {
			blobHash0 = common.Bytes2Hex(sidecar.BlobHashes()[0][:])
			commit0 = common.Bytes2Hex(sidecar.Commitments[0][:])
			proofs0 = common.Bytes2Hex(sidecar.Proofs[0][:])
			blob0 = common.Bytes2Hex(sidecar.Blobs[0][:])
		}
	}

	params := ParamsItem{
		From: "0x" + common.Bytes2Hex(opts.From[:]),
		To:   "0x" + common.Bytes2Hex(tx.To()[:]),
		Data: "0x" + common.Bytes2Hex(tx.Data()),
	}
	var sidecarJson SidecarData
	if blobType {
		params.BlobVersionedHashes = append(params.BlobVersionedHashes, "0x"+blobHash0)

		sidecarJson = SidecarData{
			Commit: "0x" + commit0,
			Proof:  "0x" + proofs0,
			Blob:   "0x" + blob0,
		}
	}

	request := JsonRequest{
		Jsonrpc: "2.0",
		Method:  "eth_call",
		Params: []ParamsItem{
			params,
		},
	}

	// Generate dump files
	if dumpFile {
		now := time.Now()
		fileName := fmt.Sprintf("type%d-%d-%02d-%02d_%02d-%02d-%02d-%03d", tx.Type(),
			now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second(), now.Nanosecond()/1e6) //nolint:gomnd

		file, err := os.Create("dump-" + fileName + ".json")
		if err == nil {
			defer file.Close()
			encoder := json.NewEncoder(file)
			_ = encoder.Encode(request)
		}

		if blobType {
			file2, err := os.Create("dums-" + fileName + ".json")
			if err == nil {
				defer file2.Close()
				encoder := json.NewEncoder(file2)
				_ = encoder.Encode(sidecarJson)
			}
		}
	}

	// Generate log info
	if dumpScreen {
		log.Infof(`
			type: %d
			nonce: %d
			from: %v
			to: %v
			value: %v
			sidecarHashes0: %v
			sidecarCommit0: %v
			sidecarProofs0: %v
		`, tx.Type(), tx.Nonce(), opts.From, tx.To(), tx.Value(), blobHash0, commit0, proofs0)
	}
}

// encodeBlobData encodes data to be sent as a blob via an Ethereum blob transaction
func encodeBlobData(data []byte) (kzg4844.Blob, error) {
	dataLen := len(data)
	// 1 Blob data length = 4096 Field elements x 31 bytes/field element = 126976 = 124KB
	if dataLen > params.BlobTxFieldElementsPerBlob*(params.BlobTxBytesPerFieldElement-1) {
		log.Infof("blob data longer than allowed (length: %v, limit: %v)", dataLen, params.BlobTxFieldElementsPerBlob*(params.BlobTxBytesPerFieldElement-1))
		return kzg4844.Blob{}, ErrBlobOversizedData
	}

	elemSize := params.BlobTxBytesPerFieldElement
	blob := kzg4844.Blob{}
	fieldIndex := -1
	for i := 0; i < dataLen; i += (elemSize - 1) {
		fieldIndex++
		if fieldIndex == params.BlobTxFieldElementsPerBlob {
			break
		}
		max := i + (elemSize - 1)
		if max > dataLen {
			max = dataLen
		}
		copy(blob[fieldIndex*elemSize+1:], data[i:max])
	}
	return blob, nil
}

// makeBlobSidecar generates the necessary sidecar data to send blob in an Ethereum blob transaction
func makeBlobSidecar(blobs []kzg4844.Blob) *types.BlobTxSidecar {
	var commitments []kzg4844.Commitment
	var proofs []kzg4844.Proof

	for _, blob := range blobs {
		c, _ := kzg4844.BlobToCommitment(blob)
		p, _ := kzg4844.ComputeBlobProof(blob, c)

		commitments = append(commitments, c)
		proofs = append(proofs, p)
	}

	return &types.BlobTxSidecar{
		Blobs:       blobs,
		Commitments: commitments,
		Proofs:      proofs,
	}
}

// calculateAccInputHash calculates the accumulated input hash
func calculateAccInputHash(oldBlobAccInputHash common.Hash, lastL1InfoTreeIndex uint32, lastL1InfoTreeRoot common.Hash, timestampLimit uint64, sequencerAddress common.Address,
	zkGasLimit uint64, blobType byte, pointZ common.Hash, pointY common.Hash, blobL2HashData []byte, forcedHashData common.Hash) common.Hash {
	// Convert values to byte slices
	v1 := oldBlobAccInputHash.Bytes()
	v2 := big.NewInt(0).SetUint64(uint64(lastL1InfoTreeIndex)).Bytes()
	v3 := lastL1InfoTreeRoot.Bytes()
	v4 := big.NewInt(0).SetUint64(timestampLimit).Bytes()
	v5 := sequencerAddress.Bytes()
	v6 := big.NewInt(0).SetUint64(zkGasLimit).Bytes()
	v7 := []byte{blobType}
	v8 := pointZ.Bytes()
	v9 := pointY.Bytes()
	v10 := blobL2HashData
	v11 := forcedHashData.Bytes()

	// Add 0s to make values fixed bytes long
	for len(v1) < 32 {
		v1 = append([]byte{0}, v1...)
	}
	for len(v2) < 4 {
		v2 = append([]byte{0}, v2...)
	}
	for len(v3) < 32 {
		v3 = append([]byte{0}, v3...)
	}
	for len(v4) < 8 {
		v4 = append([]byte{0}, v4...)
	}
	for len(v5) < 20 {
		v5 = append([]byte{0}, v5...)
	}
	for len(v6) < 8 {
		v6 = append([]byte{0}, v6...)
	}
	for len(v8) < 32 {
		v8 = append([]byte{0}, v8...)
	}
	for len(v9) < 32 {
		v9 = append([]byte{0}, v9...)
	}

	if blobType == blobTypeDataTx {
		// Hash of the data
		v10 = keccak256.Hash(v10)
	} else {
		for len(v10) < 32 {
			v10 = append([]byte{0}, v10...)
		}
	}

	for len(v11) < 32 {
		v11 = append([]byte{0}, v11...)
	}

	// Keccak hash of the entire data set
	return common.BytesToHash(keccak256.Hash(v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11))
}
