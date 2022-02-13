from web3 import Web3
from hexbytes import HexBytes

IP_ADDR='18.188.235.196'
PORT='8545'

w3 = Web3(Web3.HTTPProvider('http://' + IP_ADDR + ':' + PORT))

# if w3.isConnected():
#     print( "Connected to Ethereum node" )
# else:
#     print( "Failed to connect to Ethereum node!" )

def get_transaction(tx):
    tx = w3.eth.get_transaction(tx)   #YOUR CODE HERE
    return tx

# Return the gas price used by a particular transaction,
#   tx is the transaction
def get_gas_price(tx):
    tx = get_transaction(tx)
    gas_price = tx['gasPrice']
    return gas_price

def get_gas(tx):
    tx = w3.eth.get_transaction_receipt(tx)
    gas = tx['gasUsed']
    return gas

def get_transaction_cost(tx):
    tx_cost = get_gas(tx) * get_gas_price(tx)
    return tx_cost

def get_block_cost(block_num):
    bk = w3.eth.get_block(block_num)
    txns = bk['transactions']
    block_cost = 0
    for txn in txns:
        txn_cost = get_transaction_cost(txn.hex())
        block_cost += txn_cost
    return block_cost

# Return the hash of the most expensive transaction
def get_most_expensive_transaction(block_num):
    max_tx = HexBytes('0xf7f4905225c0fde293e2fd3476e97a9c878649dd96eb02c86b86be5b92d826b6')

    return max_tx
