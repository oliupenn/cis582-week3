from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()

def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """
        
""" Helper Methods (skeleton code for you to implement) """

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    
    return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
    w3 = Web3()
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys

    return eth_sk, eth_pk

def check_sig(payload,sig):
    platform = payload.get('platform')
    pk = payload.get('pk')
    if platform == 'Ethereum':
        eth_encoded_msg = eth_account.messages.encode_defunct(text=json.dumps(payload))
        return eth_account.Account.recover_message(eth_encoded_msg, signature=sig) == pk
    elif platform == 'Algorand':
        return algosdk.util.verify_bytes(json.dumps(payload).encode('utf-8'), sig, pk)

def fill_order(order,txes=[]):
    new_order = order
    g.session.add(new_order)
    g.session.commit()
    unfilled_orders = g.session.query(Order).filter(Order.filled == None).all()

    for old_order in unfilled_orders:
        if new_order.filled == None:
            if new_order.sell_currency == old_order.buy_currency:
                if new_order.buy_currency == old_order.sell_currency:
                    new_fx = new_order.sell_amount / new_order.buy_amount
                    old_fx = old_order.buy_amount / old_order.sell_amount
                    if new_fx >= old_fx:
                        curr_timestamp = datetime.now()
                        new_order.filled = curr_timestamp
                        old_order.filled = curr_timestamp
                        new_order.counterparty_id = old_order.id
                        old_order.counterparty_id = new_order.id
                        session.commit()
                        if new_order.buy_amount > old_order.sell_amount:
                            child = dict()
                            child['sender_pk'] = new_order.sender_pk
                            child['receiver_pk'] = new_order.receiver_pk
                            child['buy_currency'] = new_order.buy_currency
                            child['sell_currency'] = new_order.sell_currency
                            child['buy_amount'] = new_order.buy_amount - old_order.sell_amount
                            child['sell_amount'] = (new_order.buy_amount - old_order.sell_amount) * 1.01 * new_fx
                            child['creator_id'] = new_order.id
                            process_order(child)
                        if old_order.sell_amount > new_order.buy_amount:
                            child = dict()
                            child['sender_pk'] = old_order.sender_pk
                            child['receiver_pk'] = old_order.receiver_pk
                            child['buy_currency'] = old_order.buy_currency
                            child['sell_currency'] = old_order.sell_currency
                            child['sell_amount'] = old_order.sell_amount - new_order.buy_amount
                            child['buy_amount'] = (old_order.sell_amount - new_order.buy_amount) * 0.99 * old_fx
                            child['creator_id'] = old_order.id
                            process_order(child)
  
def log_message(d):
    # Takes input dictionary d and writes it to the Log table
    # Hint: use json.dumps or str() to get it in a nice string form
    new_log = Log(message=json.dumps(d))
    g.session.add(new_log)
    g.session.commit()
  
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

    pass

""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            eth_sk, eth_pk = get_eth_keys()
            return jsonify( eth_pk )
        if content['platform'] == "Algorand":
            algo_sk, algo_pk = get_algo_keys()
            return jsonify( algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        
        # 2. Add the order to the table
        
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)

        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        
        # 4. Execute the transactions
        
        # If all goes well, return jsonify(True). else return jsonify(False)
        sig = content.get('sig')
        payload = content.get('payload')
        if check_sig(payload, sig): # TODO: Check the signature
            sender_pk = payload['sender_pk']
            receiver_pk = payload['receiver_pk']
            buy_currency = payload['buy_currency']
            sell_currency = payload['sell_currency']
            buy_amount = payload['buy_amount']
            sell_amount = payload['sell_amount']
            order = Order(sender_pk=sender_pk,receiver_pk=receiver_pk,buy_currency=buy_currency,sell_currency=sell_currency,buy_amount=buy_amount,sell_amount=sell_amount)
            g.session.add(order)
            g.session.commit()
        else:
            log_message(payload)
            return jsonify(False)
        fill_order(order) # TODO: Fill the order
        return jsonify(True)

@app.route('/order_book')
def order_book():
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk", "sender_pk" ]
    orders = g.session.query(Order)
    result = []

    for order in orders:
        data = dict()
        data['sender_pk'] = order.sender_pk
        data['receiver_pk'] = order.receiver_pk
        data['buy_currency'] = order.buy_currency
        data['sell_currency'] = order.sell_currency
        data['buy_amount'] = order.buy_amount
        data['sell_amount'] = order.sell_amount
        data['signature'] = order.signature
        # data['tx_id'] = order.tx_id
        result.append(data)

if __name__ == '__main__':
    app.run(port='5002')
