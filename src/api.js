// Blockchain routes
router.get('/blockchain/status', (req, res) => {
    res.json({
        status: 'success',
        data: {
            height: blockchain.getLatestBlock().index,
            difficulty: blockchain.getDifficulty(),
            network: 'mainnet'
        }
    });
});

// Wallet routes
router.post('/wallets/create', (req, res) => {
    const wallet = walletManager.createWallet();
    res.json({
        status: 'success',
        data: {
            address: wallet.address,
            publicKey: wallet.publicKey
        }
    });
});

// Mining routes
router.post('/mining/mine', (req, res) => {
    const { address } = req.body;
    if (!address) {
        return res.status(400).json({
            status: 'error',
            message: 'Miner address is required'
        });
    }

    const block = blockchain.minePendingTransactions(address);
    res.json({
        status: 'success',
        data: {
            block: {
                index: block.index,
                timestamp: block.timestamp,
                transactions: block.transactions,
                hash: block.hash,
                previousHash: block.previousHash
            }
        }
    });
});

// Transaction routes
router.post('/transactions/send', (req, res) => {
    const { fromAddress, toAddress, amount, privateKey } = req.body;
    
    if (!fromAddress || !toAddress || !amount || !privateKey) {
        return res.status(400).json({
            status: 'error',
            message: 'Missing required fields'
        });
    }

    try {
        const transaction = new Transaction(fromAddress, toAddress, amount);
        transaction.signTransaction(privateKey);
        blockchain.addTransaction(transaction);
        
        res.json({
            status: 'success',
            data: {
                transaction: {
                    fromAddress: transaction.fromAddress,
                    toAddress: transaction.toAddress,
                    amount: transaction.amount,
                    timestamp: transaction.timestamp,
                    signature: transaction.signature
                }
            }
        });
    } catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message
        });
    }
});

// Smart contract routes
router.post('/contracts/deploy', (req, res) => {
    console.log('Received contract deployment request');
    const { contractCode, deployerAddress, privateKey } = req.body;
    
    if (!contractCode || !deployerAddress || !privateKey) {
        console.log('Missing required fields:', { contractCode: !!contractCode, deployerAddress: !!deployerAddress, privateKey: !!privateKey });
        return res.status(400).json({
            status: 'error',
            message: 'Missing required fields'
        });
    }

    try {
        console.log('Deploying contract...');
        const contract = smartContracts.deployContract(contractCode, deployerAddress, privateKey);
        console.log('Contract deployed successfully:', contract.address);
        
        res.json({
            status: 'success',
            data: {
                contract: {
                    address: contract.address,
                    code: contract.code,
                    state: contract.state,
                    deployer: contract.deployer
                }
            }
        });
    } catch (error) {
        console.error('Contract deployment failed:', error);
        res.status(400).json({
            status: 'error',
            message: error.message
        });
    }
});

router.post('/contracts/:address/call', (req, res) => {
    const { address } = req.params;
    const { method, params, callerAddress, privateKey } = req.body;
    
    if (!method || !callerAddress || !privateKey) {
        return res.status(400).json({
            status: 'error',
            message: 'Missing required fields'
        });
    }

    try {
        const result = smartContracts.callContract(address, method, params, callerAddress, privateKey);
        res.json({
            status: 'success',
            data: {
                result,
                contract: {
                    address,
                    state: smartContracts.getContractState(address)
                }
            }
        });
    } catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message
        });
    }
});

router.get('/contracts/:address/state', (req, res) => {
    const { address } = req.params;
    
    try {
        const state = smartContracts.getContractState(address);
        res.json({
            status: 'success',
            data: {
                address,
                state
            }
        });
    } catch (error) {
        res.status(400).json({
            status: 'error',
            message: error.message
        });
    }
}); 