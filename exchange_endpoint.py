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
import sys

from models import Base, Order, Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


""" Suggested helper methods """

def check_sig(payload,sig):
  platform = payload.get('platform')
  pk = payload.get('pk')
  if platform == 'Ethereum':
      eth_encoded_msg = eth_account.messages.encode_defunct(text=json.dumps(payload))
      if eth_account.Account.recover_message(eth_encoded_msg, signature=eth_sig_obj.signature.hex()) == pk:
          result = True
      else:
          result = False
  elif platform == 'Algorand':
      if algosdk.util.verify_bytes(json.dumps(payload).encode('utf-8'), sig, pk):
          result = True
      else:
          result = False

def fill_order(order,txes=[]):
    sender_pk = order.get('sender_pk')
    receiver_pk = order.get('receiver_pk')
    buy_ccy = order.get('buy_currency')
    sell_ccy = order.get('sell_currency')
    buy_amt = order.get('buy_amount')
    sell_amt = order.get('sell_amount')
    creator_id = order.get('creator_id')
    
    if creator_id != None:
        new_order = Order(sender_pk=sender_pk, receiver_pk=receiver_pk, buy_currency=buy_ccy, sell_currency=sell_ccy, buy_amount=buy_amt, sell_amount=sell_amt, creator_id=creator_id)
    else:
        new_order = Order(sender_pk=sender_pk, receiver_pk=receiver_pk, buy_currency=buy_ccy, sell_currency=sell_ccy, buy_amount=buy_amt, sell_amount=sell_amt)
    
    session.add(new_order)
    session.commit()
    unfilled_orders = session.query(Order).filter(Order.filled == None).all()

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

""" End of helper methods """



@app.route('/trade', methods=['POST'])
def trade():
    print("In trade endpoint")
    if request.method == "POST":
        content = request.get_json(silent=True)
        print( f"content = {json.dumps(content)}" )
        columns = [ "sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform" ]
        fields = [ "sig", "payload" ]

        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
        
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
            
        #Your code here
        #Note that you can access the database session using g.session

        # TODO: Check the signature
        sig = content.get('sig')
        payload = content.get('payload')
        if check_sig(payload, sig):
        # TODO: Add the order to the database
          sender_pk = payload['sender_pk']
          receiver_pk = payload['receiver_pk']
          buy_currency = payload['buy_currency']
          sell_currency = payload['sell_currency']
          buy_amount = payload['buy_amount']
          sell_amount = payload['sell_amount']
          tx_id = payload['tx_id']
          order = Order(sender_pk=sender_pk,receiver_pk=receiver_pk,buy_currency=buy_currency,sell_currency=sell_currency,buy_amount=buy_amount,sell_amount=sell_amount,tx_id=tx_id)
          g.session.add(order)
          g.session.commit()
        # TODO: Fill the order
          fill_order(order)
        # TODO: Be sure to return jsonify(True) or jsonify(False) depending on if the method was successful
          return jsonify(True)
        else:
          return jsonify(False)

@app.route('/order_book')
def order_book():
    #Your code here
    #Note that you can access the database session using g.session
  result = []
  orders = g.session.query(Order).all()
  for order in orders:
      order_dict = {}
      order_dict['sender_pk'] = order.sender_pk
      order_dict['receiver_pk'] = order.receiver_pk
      order_dict['buy_currency'] = order.buy_currency
      order_dict['sell_currency'] = order.sell_currency
      order_dict['buy_amount'] = order.buy_amount
      order_dict['sell_amount'] = order.sell_amount
      order_dict['signature'] = order.signature
      order_dict['tx_id'] = order.tx_id
      result.append(order_dict)
  return jsonify(result)

if __name__ == '__main__':
    app.run(port='5002')
