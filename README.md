# Straz Blockchain

A Python-based blockchain implementation with smart contract support and proof-of-stake consensus.

## Features

- Blockchain implementation with proof-of-work mining
- Smart contract support
- Wallet management
- RESTful API interface
- Proof-of-stake consensus mechanism

## Setup

1. Clone the repository:
```bash
git clone https://github.com/willruzycki/Straz.git
cd Straz
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the API server:
```bash
python api.py
```

The server will start on `http://localhost:5002`

## API Endpoints

- `GET /` - List all available routes
- `GET /api/blockchain` - Get blockchain status
- `GET /api/block/<index>` - Get block by index
- `POST /api/transaction` - Create a new transaction
- `POST /api/mine` - Mine a new block
- `POST /api/wallet` - Create a new wallet
- `GET /api/wallet/<address>` - Get wallet balance
- `POST /api/contracts` - Deploy a new smart contract
- `GET /api/contract/<address>` - Get contract information
- `POST /api/contract/transaction` - Create a contract transaction
- `POST /api/validator` - Register a new validator
- `GET /api/validator/<address>` - Get validator information

## License

MIT 