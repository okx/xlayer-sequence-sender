package config

// DefaultValues is the default configuration
const DefaultValues = `
ForkUpgradeBatchNumber = 0
ForkUpgradeNewForkId = 0

[Log]
Environment = "development" # "production" or "development"
Level = "info"
Outputs = ["stderr"]

[SequenceSender]
IsValidiumMode = false
WaitPeriodSendSequence = "15s"
LastBatchVirtualizationTimeMaxWaitPeriod = "10s"
L1BlockTimestampMargin = "30s"
MaxTxSizeForL1 = 131072
L2Coinbase = "0xfa3b44587990f97ba8b6ba7e230a5f0e95d14b3d"
PrivateKey = {Path = "./test/sequencer.keystore", Password = "testonly"}
SequencesTxFileName = "sequencesender.json"
GasOffset = 80000
WaitPeriodPurgeTxFile = "15m"
MaxPendingTx = 1
	[SequenceSender.StreamClient]
		Server = "127.0.0.1:6900"
	[SequenceSender.EthTxManager]
		FrequencyToMonitorTxs = "1s"
		WaitTxToBeMined = "2m"
		GetReceiptMaxTime = "250ms"
		GetReceiptWaitInterval = "1s"
		PrivateKeys = [
			{Path = "./test/sequencer.keystore", Password = "testonly"},
		]
		ForcedGas = 0
		GasPriceMarginFactor = 1
		MaxGasPriceLimit = 0
		PersistenceFilename = "ethtxmanager.json"
		ReadPendingL1Txs = false
		SafeStatusL1NumberOfBlocks = 0
		FinalizedStatusL1NumberOfBlocks = 0
			[SequenceSender.EthTxManager.Etherman]
				URL = "http://127.0.0.1:8545"
				MultiGasProvider = false
				L1ChainID = 1337
`
