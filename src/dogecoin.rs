use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::encode;
use bitcoin::hashes::hex::ToHex;
use bitcoin::BlockHash;
use bitcoin_hashes;
use bitcoin_hashes::hex::FromHex;
use bitcoincore_rpc::bitcoincore_rpc_json::GetBlockchainInfoResult;
use bitcoincore_rpc::{json, Auth, Client, Error, RpcApi};
use chrono::Duration;
use failure::Fail;
use failure::ResultExt;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use std::thread;
//use std::result::Result;

use std::str::FromStr;

use wagyu_dogecoin::{
    format::DogecoinFormat, wordlist::*, DogecoinAddress, DogecoinAmount, DogecoinDerivationPath,
    DogecoinExtendedPrivateKey, DogecoinExtendedPublicKey, DogecoinMnemonic, DogecoinNetwork,
    DogecoinPrivateKey, DogecoinPublicKey, DogecoinTransaction, DogecoinTransactionInput,
    DogecoinTransactionOutput, DogecoinTransactionParameters, DogecoinWordlist,
    Mainnet as DogecoinMainnet, Outpoint, SignatureHash,
};
use wagyu_model::{
    crypto::hash160, AddressError, AmountError, DerivationPathError, ExtendedPrivateKeyError,
    ExtendedPublicKeyError, Mnemonic, MnemonicCount, MnemonicError, MnemonicExtended, PrivateKey,
    PrivateKeyError, PublicKey, PublicKeyError, Transaction, TransactionError,
};
type Result<T = (), E = Error> = std::result::Result<T, E>;

const DOGEEXP: f64 = 100000000.0;
#[derive(Debug, Clone)]
pub struct InputTrans {
    pub txid: String,
    pub vin: u32,
    pub wif: String,
}
#[derive(Debug, Clone)]
pub struct OutputTrans {
    pub addr: String,
    pub amt: u64,
}
trait BitcoinCoreRpcResultExt<T> {
    fn into_option(self) -> Result<Option<T>>;
}

impl<T> BitcoinCoreRpcResultExt<T> for Result<T, bitcoincore_rpc::Error> {
    fn into_option(self) -> Result<Option<T>> {
        match self {
            Ok(ok) => Ok(Some(ok)),
            Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(
                bitcoincore_rpc::jsonrpc::error::RpcError { code: -8, .. },
            ))) => Ok(None),
            Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(
                bitcoincore_rpc::jsonrpc::error::RpcError { message, .. },
            ))) if message.ends_with("not found") => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
}

#[derive(Debug, Fail)]
pub enum CLIError {
    #[fail(display = "{}", _0)]
    AddressError(AddressError),

    #[fail(display = "{}", _0)]
    AmountError(AmountError),

    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "{}", _0)]
    DerivationPathError(DerivationPathError),

    #[fail(display = "{}", _0)]
    ExtendedPrivateKeyError(ExtendedPrivateKeyError),

    #[fail(display = "{}", _0)]
    ExtendedPublicKeyError(ExtendedPublicKeyError),

    #[fail(display = "invalid derived mnemonic for a given private spend key")]
    InvalidMnemonicForPrivateSpendKey,

    #[fail(display = "{}", _0)]
    PrivateKeyError(PrivateKeyError),

    #[fail(display = "{}", _0)]
    PublicKeyError(PublicKeyError),

    #[fail(display = "{}", _0)]
    MnemonicError(MnemonicError),

    #[fail(display = "{}", _0)]
    TransactionError(wagyu_model::TransactionError),

    #[fail(display = "unsupported mnemonic language")]
    UnsupportedLanguage,
}
impl From<AddressError> for CLIError {
    fn from(error: AddressError) -> Self {
        CLIError::AddressError(error)
    }
}

impl From<AmountError> for CLIError {
    fn from(error: AmountError) -> Self {
        CLIError::AmountError(error)
    }
}

impl From<core::num::ParseIntError> for CLIError {
    fn from(error: core::num::ParseIntError) -> Self {
        CLIError::Crate("parse_int", format!("{:?}", error))
    }
}

impl From<DerivationPathError> for CLIError {
    fn from(error: DerivationPathError) -> Self {
        CLIError::DerivationPathError(error)
    }
}

impl From<ExtendedPrivateKeyError> for CLIError {
    fn from(error: ExtendedPrivateKeyError) -> Self {
        CLIError::ExtendedPrivateKeyError(error)
    }
}

impl From<ExtendedPublicKeyError> for CLIError {
    fn from(error: ExtendedPublicKeyError) -> Self {
        CLIError::ExtendedPublicKeyError(error)
    }
}

impl From<hex::FromHexError> for CLIError {
    fn from(error: hex::FromHexError) -> Self {
        CLIError::Crate("hex", format!("{:?}", error))
    }
}

impl From<MnemonicError> for CLIError {
    fn from(error: MnemonicError) -> Self {
        CLIError::MnemonicError(error)
    }
}

impl From<PrivateKeyError> for CLIError {
    fn from(error: PrivateKeyError) -> Self {
        CLIError::PrivateKeyError(error)
    }
}

impl From<PublicKeyError> for CLIError {
    fn from(error: PublicKeyError) -> Self {
        CLIError::PublicKeyError(error)
    }
}

impl From<serde_json::error::Error> for CLIError {
    fn from(error: serde_json::error::Error) -> Self {
        CLIError::Crate("serde_json", format!("{:?}", error))
    }
}

impl From<wagyu_model::TransactionError> for CLIError {
    fn from(error: wagyu_model::TransactionError) -> Self {
        CLIError::TransactionError(error)
    }
}

/// Represents parameters for a Dogecoin transaction input
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DogecoinInput {
    pub txid: String,
    pub vout: u32,
    pub amount: Option<u64>,
    pub address: Option<String>,
    #[serde(rename(deserialize = "privatekey"))]
    pub private_key: Option<String>,
    #[serde(rename(deserialize = "scriptPubKey"))]
    pub script_pub_key: Option<String>,
    #[serde(rename(deserialize = "redeemScript"))]
    pub redeem_script: Option<String>,
}
/// Represents a generic wallet to output
#[derive(Serialize, Debug, Default)]
pub struct DogecoinWallet {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compressed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}
impl DogecoinWallet {
    pub fn create_addr() -> (
        DogecoinPrivateKey<DogecoinMainnet>,
        DogecoinPublicKey<DogecoinMainnet>,
        DogecoinAddress<DogecoinMainnet>,
    ) {
        let rng = &mut rand::thread_rng();
        let private_key = DogecoinPrivateKey::<DogecoinMainnet>::new(rng).unwrap();
        let public_key = private_key.to_public_key();
        let address = public_key.to_address(&DogecoinFormat::P2PKH).unwrap();

        return (private_key, public_key, address);
    }

    pub fn to_raw_transaction<N: DogecoinNetwork>(
        inputs: &Vec<DogecoinInput>,
        outputs: &Vec<&str>,
        version: u32,
        lock_time: u32,
    ) -> Result<Self, CLIError> {
        let mut transaction_inputs = vec![];
        for input in inputs {
            let transaction_input = DogecoinTransactionInput::<N>::new(
                hex::decode(&input.txid)?,
                input.vout,
                None,
                None,
                None,
                None,
                None,
                SignatureHash::SIGHASH_ALL,
            )?;
            transaction_inputs.push(transaction_input);
        }

        let mut transaction_outputs = vec![];
        for output in outputs {
            let values: Vec<&str> = output.split(":").collect();
            let address = DogecoinAddress::<N>::from_str(values[0])?;

            transaction_outputs.push(DogecoinTransactionOutput::new(
                &address,
                DogecoinAmount::from_satoshi(i64::from_str(values[1])?)?,
            )?);
        }

        let transaction_parameters = DogecoinTransactionParameters::<N> {
            version,
            inputs: transaction_inputs,
            outputs: transaction_outputs,
            lock_time,
            segwit_flag: false,
        };

        let transaction = DogecoinTransaction::<N>::new(&transaction_parameters)?;

        let raw_transaction_hex = hex::encode(&transaction.to_transaction_bytes()?);

        Ok(Self {
            transaction_hex: Some(raw_transaction_hex),
            ..Default::default()
        })
    }

    pub fn to_create_transaction<N: DogecoinNetwork>(
        inputs: &Vec<DogecoinInput>,
        outputs: &Vec<&str>,
        version: u32,
        lock_time: u32,
    ) -> Result<Self, CLIError> {
        let mut input_vec = vec![];

        for input in inputs {
            let private_key =
                DogecoinPrivateKey::from_str(&input.private_key.clone().unwrap()).unwrap();
            let transaction_id = hex::decode(input.txid.clone()).unwrap();
            let address = DogecoinAddress::<N>::from_str(&input.address.clone().unwrap())?;

            let redeem_script = match (input.redeem_script.clone(), DogecoinFormat::P2WSH) {
                (Some(script), DogecoinFormat::P2WSH) => Some(hex::decode(script).unwrap()),
                (Some(script), _) => Some(hex::decode(script).unwrap()),
                (None, DogecoinFormat::P2SH_P2WPKH) => {
                    let mut redeem_script = vec![0x00, 0x14];
                    redeem_script.extend(&hash160(
                        &private_key
                            .to_public_key()
                            .to_secp256k1_public_key()
                            .serialize_compressed(),
                    ));
                    Some(redeem_script)
                }
                (None, _) => None,
            };

            let address = match &address.format() {
                DogecoinFormat::P2WSH => {
                    DogecoinAddress::<N>::p2wsh(redeem_script.as_ref().unwrap()).unwrap()
                }
                _ => private_key.to_address(&address.format()).unwrap(),
            };
            let script_pub_key = input
                .script_pub_key
                .clone()
                .map(|script| hex::decode(script).unwrap());

            let mut transaction_input = DogecoinTransactionInput::<N>::new(
                transaction_id,
                input.vout,
                Some(address),
                Some(DogecoinAmount(input.amount.unwrap() as i64)),
                redeem_script,
                script_pub_key,
                None,
                SignatureHash::SIGHASH_ALL,
            )
            .unwrap();

            // check if P2WSH input (include any additional witness)
            transaction_input.additional_witness = None;
            transaction_input.witness_script_data = None;

            input_vec.push(transaction_input);
        }

        let mut output_vec = vec![];
        for output in outputs.iter() {
            let values: Vec<&str> = output.split(":").collect();

            let address = DogecoinAddress::<N>::from_str(values[0])?;
            let amount = DogecoinAmount::from_satoshi(i64::from_str(values[1])?)?;
            output_vec.push(DogecoinTransactionOutput::new(&address, amount).unwrap());
        }

        let transaction_parameters = DogecoinTransactionParameters::<N> {
            version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time,
            segwit_flag: false,
        };

        let mut transaction = DogecoinTransaction::<N>::new(&transaction_parameters)?;

        // Sign transaction
        for input in inputs {
            transaction = transaction
                .sign(&DogecoinPrivateKey::from_str(&input.private_key.clone().unwrap()).unwrap())
                .unwrap();
        }

        let signed_transaction = hex::encode(&transaction.to_transaction_bytes().unwrap());
        let transaction_id = hex::encode(&transaction.to_transaction_id()?.to_string());
        Ok(Self {
            transaction_id: Some(transaction_id),
            transaction_hex: Some(signed_transaction),
            ..Default::default()
        })
    }
}

pub struct DogeClient {
    //pub wallet: DogecoinWallet,
    pub client: bitcoincore_rpc::Client,
}

impl DogeClient {
    pub fn new(rpc_url: String, user: String, password: String) -> Result<Self> {
        let auth = Auth::UserPass(user.clone(), password.clone());
        log::info!("Connecting to Dogecoin Core at {}", rpc_url);

        let client = Client::new(&rpc_url, auth)
            .context("failed to connect to RPC URL")
            .unwrap();
        Ok(Self { client })
    }
    pub(crate) fn block_header_info(
        &self,
        hash: BlockHash,
    ) -> Result<Option<json::GetBlockHeaderResult>> {
        self.client.get_block_header_info(&hash).into_option()
    }
    pub(crate) fn block_info(&self) -> Result<Option<GetBlockchainInfoResult>> {
        self.client.get_blockchain_info().into_option()
    }
    pub fn get_raw_transaction(&self, tx_str: String) -> Result<Option<bitcoin::Transaction>> {
        let txid = bitcoin::Txid::from_str(&tx_str).unwrap();
        self.client.get_raw_transaction(&txid).into_option()
    }
    pub fn send_raw_transaction(&self, tx_str: String) -> Result<Option<bitcoin::Txid>> {
        let tx_bytes = Vec::from_hex(&tx_str.to_owned()).unwrap();
        let tx: bitcoin::Transaction = encode::deserialize(&tx_bytes).unwrap();

        self.client.send_raw_transaction(&tx).into_option()
    }
    pub fn get_raw_transaction_info(
        &self,
        tx_str: String,
    ) -> Result<Option<json::GetRawTransactionResult>> {
        let txid = bitcoin::Txid::from_str(&tx_str).unwrap();
        self.client.get_raw_transaction_info(&txid).into_option()
    }
    pub(crate) fn send_to_transfer(
        &self,
        txid_str: &str,
        wif: &str,
        script_str: &str,
        to_addr: &str,
    ) -> Option<String> {
        let redeem_script = create_drc20_script(&script_str, wif);

        if let Some(tx_hex) = transfer_drc20(txid_str, wif, &redeem_script, to_addr) {
            let tx_bytes = Vec::from_hex(&tx_hex.to_owned()).unwrap();
            let tx: bitcoin::Transaction = encode::deserialize(&tx_bytes).unwrap();
            let txid = self.client.send_raw_transaction(&tx).unwrap();

            return Some(txid.to_string());
        } else {
            return None;
        }
    }
    pub fn transfer(
        &self,
        transaction_inputs: &str,
        transaction_outputs: &str,
        b_send: bool,
    ) -> Result<(String, String), std::io::Error> {
        let inputs: &Vec<DogecoinInput> = &from_str(&transaction_inputs)?;

        let outputs = transaction_outputs.replace(&['{', '}', '"', ' '][..], "");
        let outputs: &Vec<&str> = &outputs.split(",").collect();

        let version = 1;
        let lock_time = 0;

        let transaction2 = DogecoinWallet::to_create_transaction::<DogecoinMainnet>(
            inputs, outputs, version, lock_time,
        )
        .unwrap();

        let tx_str = transaction2.transaction_hex.unwrap();

        let mut txid_str = "".to_string();

        if b_send {
            let txid = self.client.send_raw_transaction(tx_str.clone()).unwrap();

            txid_str = format!("{}", txid);
        }

        Ok((txid_str, tx_str))
    }
}

pub(crate) fn create_drc20_script(inscription: &str, wif: &str) -> bitcoin::Script {
    let priv_key = DogecoinPrivateKey::<DogecoinMainnet>::from_str(wif).unwrap();
    let public_key = priv_key
        .to_public_key()
        .to_secp256k1_public_key()
        .serialize_compressed()
        .to_vec();

    let builder = Builder::new()
        .push_opcode(opcodes::all::OP_PUSHNUM_1)
        .push_slice(&public_key[..])
        .push_opcode(opcodes::all::OP_PUSHNUM_1)
        .push_opcode(opcodes::all::OP_CHECKMULTISIGVERIFY)
        .push_slice("ord".as_bytes())
        .push_slice("text/plain;charset=utf-8".as_bytes())
        .push_slice(inscription.as_bytes())
        .push_opcode(opcodes::all::OP_DROP)
        .push_opcode(opcodes::all::OP_DROP)
        .push_opcode(opcodes::all::OP_DROP)
        .into_script();
    return builder;
}

pub(crate) fn transfer_drc20(
    utxo_str: &str,
    wif: &str,
    redeem_script: &bitcoin::Script,
    to_addr: &str,
) -> Option<String> {
    let Ok(from_addr) = DogecoinAddress::<DogecoinMainnet>::p2wsh(&redeem_script.to_bytes()) else {
        return None;
    };
    let input = DogecoinInput {
        txid: utxo_str.to_string(),
        vout: 0,
        amount: Some(0), // invalid input parameters
        address: Some(from_addr.to_string()),
        private_key: Some(wif.to_string()),
        script_pub_key: None,
        redeem_script: Some(redeem_script.to_hex()),
    };

    let version = 1;
    let lock_time = 0;
    let base_amt = 100000;

    let output = format!("{}:{}", to_addr, base_amt);

    let Ok(transaction2) = DogecoinWallet::to_create_transaction::<DogecoinMainnet>(
        &vec![input],
        &vec![&output],
        version,
        lock_time,
    ) else {
        return None;
    };

    Some(transaction2.transaction_hex.unwrap().to_string())
}

pub(crate) fn send_to_sig_addr(
    client: &DogeClient,
    txid_str: &str,
    vin: u32,
    wif: &str,
    script_str: &str,
    tx_fee: f64,
) -> Option<String> {
    let redeem_script = create_drc20_script(&script_str, wif);
    let sig_addr = DogecoinAddress::<DogecoinMainnet>::p2wsh(&redeem_script.to_bytes()).unwrap();
    //let to_addr = "DMciRU72ZTvriwwNVkiPWZUuXA2DDzqErA";

    let input = InputTrans {
        txid: txid_str.to_string(),
        vin: vin,
        wif: wif.to_string(),
    };
    let txin = client
        .get_raw_transaction(input.txid.clone())
        .unwrap()
        .unwrap();
    let vin = input.vin as usize;
    let amt_in = txin.output[vin].value;
    let address = DogecoinPrivateKey::<DogecoinMainnet>::from_str(&input.wif.clone())
        .unwrap()
        .to_address(&DogecoinFormat::P2PKH)
        .unwrap();
    if amt_in < (2.0 * tx_fee * DOGEEXP) as u64 {
        return None;
    }
    let input_str = format!("[{{\"txid\":\"{}\", \"vout\":{}, \"amount\":{}, \"address\":\"{}\",\"privatekey\":\"{}\"}}]",
        input.txid, input.vin, amt_in, address, input.wif);
    let mut output_str: String = "{{".to_string();
    let amt_out = (tx_fee * DOGEEXP) as u64;
    let output = OutputTrans {
        addr: sig_addr.to_string(),
        amt: amt_out,
    };
    let out_str = format!("{}:{}", output.addr, output.amt);
    output_str.push_str(&out_str);
    if amt_in - 2 * amt_out > 500000 {
        let output = OutputTrans {
            addr: address.to_string(),
            amt: amt_in - 2 * amt_out,
        };
        let out_str = format!(",{}:{}", output.addr, output.amt);
        output_str.push_str(&out_str);
    }
    output_str.push_str("}}");

    println!("input str, {}", input_str);
    println!("output str, {}", output_str);

    match client.transfer(&input_str, &output_str, true) {
        Ok(res) => return Some(res.0),
        Err(_e) => {
            return None;
        }
    }
}
