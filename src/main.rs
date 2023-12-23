mod dogecoin;
use serde::Deserialize;
use std::fs;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
#[derive(Debug, Clone)]
struct TransferInfo {
    wif: String,
    to_addr: String,
    inscript: String,
    txid: String,
}

#[derive(Deserialize, Debug, Clone)]
struct DrcTransaction {
    from_addr: String,
    wif: String,
    to_addr: String,
    utxo: String,
    vin: u32,
    tx_fee: f64,
    amt: u128,
}
#[derive(Deserialize, Debug, Clone)]
struct Operator {
    op: String,
    tick: String,
    rpc_url: String,
    username: String,
    password: String,
    transactions: Vec<DrcTransaction>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Please provide configuration file <*.json>");
        return;
    }
    let file = fs::File::open(args[1].to_string()).expect("file should open read only");
    let auguments: Operator = serde_json::from_reader(file).expect("file should be proper JSON");
    println!("{:?}", auguments);
    if auguments.op == "transfer" {
        drc20_transfer(auguments);
    } else {
        println!("OP {} doesn't support now", auguments.op);
    }
}

fn drc20_transfer(auguments: Operator) {
    let tick = auguments.tick;
    let rpc_url = auguments.rpc_url.clone();
    let username = auguments.username.clone();
    let password = auguments.password.clone();
    let mut transfer_vec = Vec::new();
    let trx_len = auguments.transactions.len();
    let client =
        dogecoin::DogeClient::new(rpc_url.clone(), username.clone(), password.clone()).unwrap();
    for i in 0..trx_len {
        let from_addr = auguments.transactions[i].from_addr.clone();
        let amt = auguments.transactions[i].amt * 100000000;
        let to_addr = auguments.transactions[i].to_addr.clone();
        let wif = auguments.transactions[i].wif.clone();
        let txid_str = auguments.transactions[i].utxo.clone();
        let vin = auguments.transactions[i].vin;
        let tx_fee = auguments.transactions[i].tx_fee;
        println!("transfer {tick} from {from_addr} to {to_addr}: {amt}");
        let script_str = format!(
            "{{\"amt\":\"{}\",\"op\":\"transfer\",\"p\":\"drc-20\",\"tick\":\"{}\"}}",
            amt, tick
        );

        let Some(txid) =
            dogecoin::send_to_sig_addr(&client, &txid_str, vin, &wif, script_str.as_str(), tx_fee)
        else {
            println!("send sig addr failed in {}", from_addr);
            break;
        };

        println!("push transfer info {}:{}", txid, script_str);
        transfer_vec.push(TransferInfo {
            wif: wif.to_string(),
            to_addr: to_addr,
            inscript: script_str.to_string(),
            txid: txid.to_string(),
        });

        thread::sleep(Duration::from_micros(5));
    }

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || loop {
        let mut index = 0;
        while index < transfer_vec.len() {
            let item = transfer_vec[index].clone();
            let txid_str = item.txid.clone();
            println!("finding {}", txid_str);
            match client.get_raw_transaction_info(txid_str) {
                Ok(res) => match res {
                    Some(res) => match res.confirmations {
                        None => {}
                        Some(confirms) => {
                            if confirms >= 1 {
                                println!("send transfer info {:?}", item);
                                tx.send(item.clone()).unwrap();
                                transfer_vec.remove(index);
                                continue;
                            }
                        }
                    },
                    None => {}
                },
                Err(_e) => {}
            }

            index = index + 1;
            thread::sleep(Duration::from_secs(5));
        }
    });

    let client = dogecoin::DogeClient::new(rpc_url, username, password).unwrap();
    for received in rx {
        let txid_str = received.txid.as_str();
        let wif = received.wif.as_str();
        let script_str = received.inscript.as_str();
        let to_addr = received.to_addr.as_str();

        for _ in 0..20 {
            if let Some(txid) = client.send_to_transfer(txid_str, wif, script_str, to_addr) {
                println!("Send Drc20: to {} in {}", to_addr, txid);
                break;
            } else {
                thread::sleep(Duration::from_secs(1));
            }
        }
        thread::sleep(Duration::from_micros(50));
    }
}
