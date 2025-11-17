use alloy::hex::{self, FromHex};
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::providers::{Provider, ProviderBuilder, WalletProvider};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{keccak256, Address, U256};
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use commonware_codec::{Encode, ReadExt};
use commonware_cryptography::Sha256;
use commonware_cryptography::{bls12381, ed25519::PrivateKey, Hasher, Signer};
use std::str::FromStr;
use summit_types::execution_request::DepositRequest;

const DEFAULT_DEPOSIT_CONTRACT: &str = "0x00000000219ab540356cBB839Cbe05303d7705Fa";
const PROTOCOL_VERSION: u32 = 1;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Ethereum RPC endpoint URL
    #[arg(long, default_value = "http://localhost:8545")]
    rpc_url: String,

    /// Private key for signing the transaction (hex format with 0x prefix)
    #[arg(long)]
    eth_private_key: String,

    /// Ed25519 private key in hex format (64 characters, no 0x prefix)
    #[arg(long)]
    ed25519_private_key: String,

    /// BLS12-381 private key in hex format (64 characters, no 0x prefix)
    #[arg(long)]
    bls_private_key: String,

    /// Withdrawal credentials address (Ethereum address for withdrawals)
    #[arg(long)]
    withdrawal_address: String,

    /// Deposit amount in gwei (default: 32000000000 = 32 ETH)
    #[arg(long, default_value_t = 32_000_000_000)]
    amount_gwei: u64,

    /// Deposit contract address
    #[arg(long, default_value = DEFAULT_DEPOSIT_CONTRACT)]
    deposit_contract: String,

    /// Transaction nonce (optional, will use pending nonce if not provided)
    #[arg(long)]
    nonce: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Create Ethereum wallet
    let eth_signer = PrivateKeySigner::from_str(&args.eth_private_key)
        .context("Failed to parse Ethereum private key")?;
    let wallet = EthereumWallet::from(eth_signer.clone());

    // Create provider with wallet
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(args.rpc_url.parse().context("Invalid RPC URL")?);

    // Parse deposit contract address
    let deposit_contract =
        Address::from_hex(&args.deposit_contract).context("Invalid deposit contract address")?;

    // Parse ed25519 private key from hex
    let ed25519_privkey_bytes = hex::decode(&args.ed25519_private_key)
        .context("Invalid hex format for ed25519 private key")?;
    if ed25519_privkey_bytes.len() != 32 {
        return Err(anyhow!(
            "Ed25519 private key must be exactly 32 bytes (64 hex characters)"
        ));
    }

    // Decode private key using commonware codec
    let ed25519_private_key = PrivateKey::read(&mut ed25519_privkey_bytes.as_slice())
        .context("Failed to decode ed25519 private key")?;

    let ed25519_public_key = ed25519_private_key.public_key();
    let ed25519_pubkey_bytes: [u8; 32] = ed25519_public_key
        .to_vec()
        .try_into()
        .map_err(|_| anyhow!("Invalid public key length"))?;

    println!("Ed25519 Public Key: {}", hex::encode(ed25519_pubkey_bytes));

    // Parse BLS12-381 private key from hex
    let bls_privkey_bytes = hex::decode(&args.bls_private_key)
        .context("Invalid hex format for BLS private key")?;
    if bls_privkey_bytes.len() != 32 {
        return Err(anyhow!(
            "BLS private key must be exactly 32 bytes (64 hex characters)"
        ));
    }

    // Decode BLS private key using commonware codec
    let bls_private_key = bls12381::PrivateKey::read(&mut bls_privkey_bytes.as_slice())
        .context("Failed to decode BLS private key")?;

    let bls_public_key = bls_private_key.public_key();
    let bls_pubkey_bytes: [u8; 48] = bls_public_key.encode().as_ref()[..48]
        .try_into()
        .map_err(|_| anyhow!("Invalid BLS public key length"))?;

    println!("BLS Public Key: {}", hex::encode(bls_pubkey_bytes));

    // Create withdrawal credentials (0x01 prefix for execution address withdrawal)
    let mut withdrawal_credentials = [0u8; 32];
    withdrawal_credentials[0] = 0x01; // ETH1 withdrawal prefix
    let withdrawal_address =
        Address::from_hex(&args.withdrawal_address).context("Invalid withdrawal address")?;
    withdrawal_credentials[12..32].copy_from_slice(withdrawal_address.as_slice());

    // Create deposit request and sign it
    let deposit_request = DepositRequest {
        node_pubkey: ed25519_public_key,
        consensus_pubkey: bls_public_key.clone(),
        withdrawal_credentials,
        amount: args.amount_gwei,
        node_signature: [0; 64],
        consensus_signature: [0; 96],
        index: 0, // not included in the signature
    };

    let protocol_version_digest = Sha256::hash(&PROTOCOL_VERSION.to_le_bytes());
    let message = deposit_request.as_message(protocol_version_digest);

    // Sign with node (ed25519) key
    let node_signature = ed25519_private_key.sign(None, &message);
    let node_signature_bytes: [u8; 64] = node_signature
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("Invalid node signature length"))?;

    // Sign with consensus (BLS) key
    let consensus_signature = bls_private_key.sign(None, &message);
    let consensus_signature_slice: &[u8] = consensus_signature.as_ref();
    let consensus_signature_bytes: [u8; 96] = consensus_signature_slice
        .try_into()
        .map_err(|_| anyhow!("Invalid consensus signature length"))?;

    // Convert amount to wei
    let deposit_amount = U256::from(args.amount_gwei) * U256::from(1_000_000_000u64);

    println!(
        "Deposit Amount: {} gwei ({} ETH)",
        args.amount_gwei,
        deposit_amount / U256::from(10).pow(U256::from(18))
    );
    println!("Withdrawal Address: {}", withdrawal_address);
    println!("Deposit Contract: {}", deposit_contract);

    // Get nonce if not provided
    let nonce = if let Some(n) = args.nonce {
        n
    } else {
        provider
            .get_transaction_count(eth_signer.address())
            .await
            .context("Failed to get transaction count")?
    };

    println!("Transaction nonce: {}", nonce);

    // Send the deposit transaction
    send_deposit_transaction(
        &provider,
        deposit_contract,
        deposit_amount,
        &ed25519_pubkey_bytes,
        &bls_pubkey_bytes,
        &withdrawal_credentials,
        &node_signature_bytes,
        &consensus_signature_bytes,
        nonce,
    )
    .await?;

    println!("\n✓ Deposit transaction submitted successfully!");
    println!(
        "  Ed25519 Public Key: {}",
        hex::encode(ed25519_pubkey_bytes)
    );
    println!("  BLS Public Key: {}", hex::encode(bls_pubkey_bytes));
    println!("  Amount: {} gwei", args.amount_gwei);
    println!("  Withdrawal Address: {}", withdrawal_address);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_deposit_transaction<P>(
    provider: &P,
    deposit_contract_address: Address,
    deposit_amount: U256,
    node_pubkey: &[u8; 32],
    consensus_pubkey: &[u8; 48],
    withdrawal_credentials: &[u8; 32],
    node_signature: &[u8; 64],
    consensus_signature: &[u8; 96],
    nonce: u64,
) -> Result<()>
where
    P: Provider + WalletProvider,
{
    // Compute the correct deposit data root for this transaction
    let deposit_data_root = compute_deposit_data_root(
        node_pubkey,
        consensus_pubkey,
        withdrawal_credentials,
        deposit_amount,
        node_signature,
        consensus_signature,
    );

    // Create deposit function call data: deposit(bytes,bytes,bytes,bytes,bytes,bytes32)
    let function_selector = &keccak256("deposit(bytes,bytes,bytes,bytes,bytes,bytes32)")[0..4];
    let mut call_data = function_selector.to_vec();

    // ABI encode parameters - calculate offsets for 6 parameters (5 dynamic + 1 fixed)
    // Offsets start after the 6 parameter slots (6 * 32 bytes)
    let offset_to_node_pubkey = 6 * 32;
    let offset_to_consensus_pubkey =
        offset_to_node_pubkey + 32 + node_pubkey.len().div_ceil(32) * 32;
    let offset_to_withdrawal_creds =
        offset_to_consensus_pubkey + 32 + consensus_pubkey.len().div_ceil(32) * 32;
    let offset_to_node_signature =
        offset_to_withdrawal_creds + 32 + withdrawal_credentials.len().div_ceil(32) * 32;
    let offset_to_consensus_signature =
        offset_to_node_signature + 32 + node_signature.len().div_ceil(32) * 32;

    // Add parameter offsets
    let mut offset_bytes = vec![0u8; 32];
    offset_bytes[28..32].copy_from_slice(&(offset_to_node_pubkey as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_consensus_pubkey as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_withdrawal_creds as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_node_signature as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_consensus_signature as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    // Add the fixed bytes32 parameter (deposit_data_root)
    call_data.extend_from_slice(&deposit_data_root);

    // Add dynamic data
    let mut length_bytes = [0u8; 32];

    // Node pubkey (32 bytes ed25519)
    length_bytes[28..32].copy_from_slice(&(node_pubkey.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(node_pubkey);

    // Consensus pubkey (48 bytes BLS)
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(consensus_pubkey.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(consensus_pubkey);
    call_data.extend_from_slice(&[0u8; 16]); // Pad 48 to 64 bytes (next 32-byte boundary)

    // Withdrawal credentials (32 bytes)
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(withdrawal_credentials.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(withdrawal_credentials);

    // Node signature (64 bytes ed25519)
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(node_signature.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(node_signature);

    // Consensus signature (96 bytes BLS)
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(consensus_signature.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(consensus_signature);

    let tx_request = TransactionRequest::default()
        .with_to(deposit_contract_address)
        .with_value(deposit_amount)
        .with_input(call_data)
        .with_gas_limit(500_000)
        .with_gas_price(1_000_000_000) // 1 gwei
        .with_nonce(nonce);

    println!("\nSending transaction...");
    let pending = provider
        .send_transaction(tx_request)
        .await
        .context("Failed to send transaction")?;

    println!("Transaction hash: {}", pending.tx_hash());
    println!("Waiting for receipt...");

    let receipt = pending
        .get_receipt()
        .await
        .context("Failed to get transaction receipt")?;

    if receipt.status() {
        println!("✓ Transaction confirmed!");
        println!("  Block: {}", receipt.block_number.unwrap_or_default());
        println!("  Gas used: {}", receipt.gas_used);
    } else {
        return Err(anyhow!("Transaction failed"));
    }

    Ok(())
}

fn compute_deposit_data_root(
    node_pubkey: &[u8; 32],
    consensus_pubkey: &[u8; 48],
    withdrawal_credentials: &[u8; 32],
    amount: U256,
    node_signature: &[u8; 64],
    consensus_signature: &[u8; 96],
) -> [u8; 32] {
    /*
    Solidity computation:
    bytes32 consensus_pubkey_hash = sha256(abi.encodePacked(consensus_pubkey, bytes16(0)));
    bytes32 pubkey_root = sha256(abi.encodePacked(node_pubkey, consensus_pubkey_hash));
    bytes32 node_signature_hash = sha256(node_signature);
    bytes32 consensus_signature_hash = sha256(abi.encodePacked(
        sha256(abi.encodePacked(consensus_signature[:64])),
        sha256(abi.encodePacked(consensus_signature[64:], bytes32(0)))
    ));
    bytes32 signature_root = sha256(abi.encodePacked(node_signature_hash, consensus_signature_hash));
    bytes32 node = sha256(abi.encodePacked(
        sha256(abi.encodePacked(pubkey_root, withdrawal_credentials)),
        sha256(abi.encodePacked(amount, bytes24(0), signature_root))
    ));
    */

    // 1. consensus_pubkey_hash = sha256(consensus_pubkey || bytes16(0))
    let mut hasher = Sha256::new();
    hasher.update(consensus_pubkey);
    hasher.update(&[0u8; 16]); // bytes16(0)
    let consensus_pubkey_hash = hasher.finalize();

    // 2. pubkey_root = sha256(node_pubkey || consensus_pubkey_hash)
    let mut hasher = Sha256::new();
    hasher.update(node_pubkey);
    hasher.update(&consensus_pubkey_hash);
    let pubkey_root = hasher.finalize();

    // 3. node_signature_hash = sha256(node_signature)
    let mut hasher = Sha256::new();
    hasher.update(node_signature);
    let node_signature_hash = hasher.finalize();

    // 4. consensus_signature_hash = sha256(sha256(consensus_signature[0:64]) || sha256(consensus_signature[64:96] || bytes32(0)))
    let mut hasher = Sha256::new();
    hasher.update(&consensus_signature[0..64]);
    let consensus_sig_part1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&consensus_signature[64..96]);
    hasher.update(&[0u8; 32]); // bytes32(0)
    let consensus_sig_part2 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&consensus_sig_part1);
    hasher.update(&consensus_sig_part2);
    let consensus_signature_hash = hasher.finalize();

    // 5. signature_root = sha256(node_signature_hash || consensus_signature_hash)
    let mut hasher = Sha256::new();
    hasher.update(&node_signature_hash);
    hasher.update(&consensus_signature_hash);
    let signature_root = hasher.finalize();

    // 6. Convert amount to 8-byte little-endian (gwei)
    let amount_gwei = amount / U256::from(10).pow(U256::from(9)); // Convert wei to gwei
    let amount_u64 = amount_gwei.to::<u64>(); // Convert to u64 (should fit for reasonable amounts)
    let amount_bytes = amount_u64.to_le_bytes(); // 8 bytes little-endian

    // 7. node = sha256(sha256(pubkey_root || withdrawal_credentials) || sha256(amount || bytes24(0) || signature_root))
    let mut hasher = Sha256::new();
    hasher.update(&pubkey_root);
    hasher.update(withdrawal_credentials);
    let left_node = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&amount_bytes);
    hasher.update(&[0u8; 24]); // bytes24(0)
    hasher.update(&signature_root);
    let right_node = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&left_node);
    hasher.update(&right_node);
    let deposit_data_root = hasher.finalize();

    let digest_bytes: &[u8] = deposit_data_root.as_ref();
    digest_bytes
        .try_into()
        .expect("SHA-256 digest is always 32 bytes")
}
