# Deposit CLI

A command-line tool for sending validator deposit transactions to the Ethereum deposit contract.

## Installation

```bash
cargo build --release
```

## Usage

```bash
./target/release/deposit-cli \
  --eth-private-key "0xYOUR_ETH_PRIVATE_KEY" \
  --ed25519-private-key "YOUR_ED25519_PRIVATE_KEY_HEX" \
  --withdrawal-address "0xYOUR_WITHDRAWAL_ADDRESS" \
  [OPTIONS]
```

### Required Arguments

- `--eth-private-key`: Ethereum private key for signing the transaction (hex format with 0x prefix)
- `--ed25519-private-key`: Ed25519 private key in hex format (64 characters, no 0x prefix)
- `--withdrawal-address`: Ethereum address where withdrawn funds will be sent

### Optional Arguments

- `--rpc-url`: Ethereum RPC endpoint URL (default: `http://localhost:8545`)
- `--amount-gwei`: Deposit amount in gwei (default: `32000000000` = 32 ETH)
- `--deposit-contract`: Deposit contract address (default: `0x00000000219ab540356cBB839Cbe05303d7705Fa`)
- `--nonce`: Transaction nonce (optional, auto-detected if not provided)

## Example

Send a 32 ETH deposit:

```bash
./target/release/deposit-cli \
  --eth-private-key "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" \
  --ed25519-private-key "d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3" \
  --withdrawal-address "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" \
  --rpc-url "http://localhost:8545"
```

## Output

The tool will display:
- Ed25519 public key (derived from the private key)
- Deposit amount and withdrawal address
- Transaction hash
- Transaction receipt with block number and gas used

## Notes

- The Ed25519 public key is derived from the provided private key
- The Ed25519 private key is used to sign the deposit request
- The deposit amount must be in gwei (1 ETH = 1,000,000,000 gwei)
- The tool automatically computes the deposit data root according to EIP-7251
- Transaction nonce is automatically detected if not provided
