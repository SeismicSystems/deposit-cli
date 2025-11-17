# Deposit CLI

A command-line tool for sending validator deposit transactions to the Ethereum deposit contract with dual-signature support (Ed25519 + BLS12-381).

## Installation

```bash
cargo build --release
```

## Usage

```bash
./target/release/deposit-cli \
  --eth-private-key "0xYOUR_ETH_PRIVATE_KEY" \
  --ed25519-private-key "YOUR_ED25519_PRIVATE_KEY_HEX" \
  --bls-private-key "YOUR_BLS_PRIVATE_KEY_HEX" \
  --withdrawal-address "0xYOUR_WITHDRAWAL_ADDRESS" \
  [OPTIONS]
```

### Required Arguments

- `--eth-private-key`: Ethereum private key for signing the transaction (hex format with 0x prefix)
- `--ed25519-private-key`: Ed25519 private key in hex format (64 characters, no 0x prefix)
- `--bls-private-key`: BLS12-381 private key in hex format (64 characters, no 0x prefix)
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
  --bls-private-key "a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4" \
  --withdrawal-address "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" \
  --rpc-url "http://localhost:8545"
```

## Output

The tool will display:
- Ed25519 public key (node key, derived from the Ed25519 private key)
- BLS12-381 public key (consensus key, derived from the BLS private key)
- Deposit amount and withdrawal address
- Transaction hash
- Transaction receipt with block number and gas used

## Notes

- Both public keys are derived from their respective private keys
- The deposit requires dual signatures:
  - Ed25519 signature (node signature, 64 bytes)
  - BLS12-381 signature (consensus signature, 96 bytes)
- Both signatures sign the same message containing the deposit data
- The deposit amount must be in gwei (1 ETH = 1,000,000,000 gwei)
- The tool automatically computes the deposit data root according to the dual-signature format
- Transaction nonce is automatically detected if not provided
- The deposit contract function signature is: `deposit(bytes node_pubkey, bytes consensus_pubkey, bytes withdrawal_credentials, bytes node_signature, bytes consensus_signature, bytes32 deposit_data_root)`
