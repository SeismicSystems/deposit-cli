use alloy::hex::{self, FromHex};
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::providers::{Provider, ProviderBuilder, WalletProvider};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{keccak256, Address, U256};
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use commonware_codec::ReadExt;
use commonware_cryptography::Sha256;
use commonware_cryptography::{ed25519::PrivateKey, Hasher, Signer};
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

    // Create withdrawal credentials (0x01 prefix for execution address withdrawal)
    let mut withdrawal_credentials = [0u8; 32];
    withdrawal_credentials[0] = 0x01; // ETH1 withdrawal prefix
    let withdrawal_address =
        Address::from_hex(&args.withdrawal_address).context("Invalid withdrawal address")?;
    withdrawal_credentials[12..32].copy_from_slice(withdrawal_address.as_slice());

    // Create deposit request and sign it
    let deposit_request = DepositRequest {
        pubkey: ed25519_public_key,
        withdrawal_credentials,
        amount: args.amount_gwei,
        signature: [0; 64],
        index: 0, // not included in the signature
    };

    let protocol_version_digest = Sha256::hash(&PROTOCOL_VERSION.to_le_bytes());
    let message = deposit_request.as_message(protocol_version_digest);
    let signature = ed25519_private_key.sign(None, &message);

    // Pad signature to 96 bytes (32 zeros + 64 byte signature)
    let mut padded_signature = [0u8; 96];
    padded_signature[32..96].copy_from_slice(signature.as_ref());

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
        &withdrawal_credentials,
        &padded_signature,
        nonce,
    )
    .await?;

    println!("\n✓ Deposit transaction submitted successfully!");
    println!(
        "  Ed25519 Public Key: {}",
        hex::encode(ed25519_pubkey_bytes)
    );
    println!("  Amount: {} gwei", args.amount_gwei);
    println!("  Withdrawal Address: {}", withdrawal_address);

    Ok(())
}

async fn send_deposit_transaction<P>(
    provider: &P,
    deposit_contract_address: Address,
    deposit_amount: U256,
    ed25519_pubkey: &[u8; 32],
    withdrawal_credentials: &[u8; 32],
    signature: &[u8; 96],
    nonce: u64,
) -> Result<()>
where
    P: Provider + WalletProvider,
{
    // Left-pad ed25519 key to 48 bytes for the contract (prepend zeros)
    let mut padded_pubkey = [0u8; 48];
    padded_pubkey[16..48].copy_from_slice(ed25519_pubkey);

    // Compute the correct deposit data root for this transaction
    let deposit_data_root = compute_deposit_data_root(
        ed25519_pubkey,
        withdrawal_credentials,
        deposit_amount,
        signature,
    );

    // Create deposit function call data: deposit(bytes,bytes,bytes,bytes32)
    let function_selector = &keccak256("deposit(bytes,bytes,bytes,bytes32)")[0..4];
    let mut call_data = function_selector.to_vec();

    // ABI encode parameters - calculate offsets for 4 parameters (3 dynamic + 1 fixed)
    let offset_to_pubkey = 4 * 32;
    let offset_to_withdrawal_creds = offset_to_pubkey + 32 + padded_pubkey.len().div_ceil(32) * 32;
    let offset_to_signature =
        offset_to_withdrawal_creds + 32 + withdrawal_credentials.len().div_ceil(32) * 32;

    // Add parameter offsets
    let mut offset_bytes = vec![0u8; 32];
    offset_bytes[28..32].copy_from_slice(&(offset_to_pubkey as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_withdrawal_creds as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_signature as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    // Add the fixed bytes32 parameter (deposit_data_root)
    call_data.extend_from_slice(&deposit_data_root);

    // Add dynamic data
    let mut length_bytes = [0u8; 32];

    // Padded pubkey (48 bytes) - already padded to 48, need to pad to next 32-byte boundary (64)
    length_bytes[28..32].copy_from_slice(&(padded_pubkey.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(&padded_pubkey);
    call_data.extend_from_slice(&[0u8; 16]); // Pad 48 to 64 bytes (next 32-byte boundary)

    // Withdrawal credentials (32 bytes) - already aligned
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(withdrawal_credentials.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(withdrawal_credentials);

    // Signature (96 bytes) - already aligned to 32-byte boundary
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(signature.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(signature);

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
    ed25519_pubkey: &[u8; 32],
    withdrawal_credentials: &[u8; 32],
    amount: U256,
    signature: &[u8; 96],
) -> [u8; 32] {
    /*
    bytes32 pubkey_root = sha256(abi.encodePacked(pubkey, bytes16(0)));
    bytes32 signature_root = sha256(abi.encodePacked(
        sha256(abi.encodePacked(signature[:64])),
        sha256(abi.encodePacked(signature[64:], bytes32(0)))
    ));
    bytes32 node = sha256(abi.encodePacked(
        sha256(abi.encodePacked(pubkey_root, withdrawal_credentials)),
        sha256(abi.encodePacked(amount, bytes24(0), signature_root))
    ));
     */

    // Left-pad ed25519 key to 48 bytes (prepend zeros)
    let mut padded_pubkey = [0u8; 48];
    padded_pubkey[16..48].copy_from_slice(ed25519_pubkey);

    // 1. pubkey_root = sha256(padded_pubkey || bytes16(0))
    let mut hasher = Sha256::new();
    hasher.update(&padded_pubkey);
    hasher.update(&[0u8; 16]); // bytes16(0)
    let pubkey_root = hasher.finalize();

    // 2. signature_root = sha256(sha256(signature[0:64]) || sha256(signature[64:96] || bytes32(0)))
    let mut hasher = Sha256::new();
    hasher.update(&signature[0..64]);
    let sig_part1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&signature[64..96]);
    hasher.update(&[0u8; 32]); // bytes32(0)
    let sig_part2 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&sig_part1);
    hasher.update(&sig_part2);
    let signature_root = hasher.finalize();

    // 3. Convert amount to 8-byte little-endian (gwei)
    let amount_gwei = amount / U256::from(10).pow(U256::from(9)); // Convert wei to gwei
    let amount_u64 = amount_gwei.to::<u64>(); // Convert to u64 (should fit for reasonable amounts)
    let amount_bytes = amount_u64.to_le_bytes(); // 8 bytes little-endian

    // 4. node = sha256(sha256(pubkey_root || withdrawal_credentials) || sha256(amount || bytes24(0) || signature_root))
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
