#!/usr/bin/python3

from algosdk.v2client import algod
from algosdk import mnemonic
from algosdk import transaction
from algosdk import account, encoding

#Connect to Algorand node maintained by PureStake
algod_address = "https://testnet-algorand.api.purestake.io/ps2"
algod_token = "B3SU4KcVKi94Jap2VXkK83xx38bsv95K5UZm2lab"
#algod_token = 'IwMysN3FSZ8zGVaQnoUIJ9RXolbQ5nRY62JRqF2H'
headers = {
   "X-API-Key": algod_token,
}

acl = algod.AlgodClient(algod_token, algod_address, headers)
min_balance = 100000 #https://developer.algorand.org/docs/features/accounts/#minimum-balance

def send_tokens( receiver_pk, tx_amount ):
    params = acl.suggested_params()
    gen_hash = params.gh
    first_valid_round = params.first
    tx_fee = params.min_fee
    last_valid_round = params.last

    sender_sk = 'PBqeVXN/PUQBp7m62XoECBzJaaM5ieDcxmaLmBbnRy2svm4CCwLNIbDCLJhWf/4aUlg6XaX7yqor9lyvtY30LA=='
    sender_mnemonic = mnemonic.from_private_key(sender_sk)
    sender_pk = mnemonic.to_public_key(sender_mnemonic)
    sender_address = account.address_from_private_key(sender_pk)
    receiver_address = account.address_from_private_key(receiver_pk)
    txn = transaction.PaymentTxn(sender_address, tx_fee, first_valid_round, last_valid_round, gen_hash, receiver_address, tx_amount)
    signed_txn = txn.sign(sender_sk)
    signed_txn.dictify()
    txid = txn.get_txid()
    return sender_pk, txid

# Function from Algorand Inc.
def wait_for_confirmation(client, txid):
    """
    Utility function to wait until the transaction is
    confirmed before proceeding.
    """
    last_round = client.status().get('last-round')
    txinfo = client.pending_transaction_info(txid)
    while not (txinfo.get('confirmed-round') and txinfo.get('confirmed-round') > 0):
        print("Waiting for confirmation")
        last_round += 1
        client.status_after_block(last_round)
        txinfo = client.pending_transaction_info(txid)
    print("Transaction {} confirmed in round {}.".format(txid, txinfo.get('confirmed-round')))
    return txinfo

# if __name__ == '__main__':
#     private_key, address = account.generate_account()
#     mnemonic_secret = "YOUR MNEMONIC HERE"
#     sk = mnemonic.to_private_key(mnemonic_secret)
#     pk = mnemonic.to_public_key(mnemonic_secret)
#     print("Private key:", private_key)
#     print("Address:", address)
