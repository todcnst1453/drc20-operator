# Drc20 Operator Tools by rust

A simple tool for drc20 operator.

## Prerequisites

1. dogecoin node: drc20 operator is an operator on dogecoin, so that you need a useful dogecoin node.
2. dogecoin account: your dogecoin account must have some balance for gas fee, since the drc20 operator is transaction on dogecoin. Being able to send transactions means having the account private key and utxo information.
3. drc20 information: make sure you have enough drc20 tokens in your account before you transfer drc20.

## Running the tools

You can build the source code, or download the executable file corresponding to the operating system in release archives

Running drc20-operator file, you need to edit a input file (json file) for transfer information. The detail of the file is in the test.json.example.

**The drc20 operation is completed in two dogecoin transfers**
The first step, generate a p2sh address with the corresponding inscription, and lock the inscription in the address. The user transfers the gas fee to the locking address and waits for the inscription to be unlocked in the future
The second step, unlock the address and transfer the inscription to the address the user wishes to transfer to, this transaction must be sending after the first transaciton is confirmed on block

When programming is running, it sends the first transaction. After that, the program check the first transaction continuously on chain, you can see "finding XXXXXXXXXX" in the command line. Once confirmed, send the second transaction immediately.

**The project is trial, and does not guarantee the security of user assets. Users are advised to make sure they fully understand the process before using it.**
