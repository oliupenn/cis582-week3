from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from models import Base, Order
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

def process_order(order):
    sender_pk = order['sender_pk']
    receiver_pk = order['receiver_pk']
    buy_ccy = order['buy_currency']
    sell_ccy = order['sell_currency']
    buy_amt = order['buy_amount']
    sell_amt = order['sell_amount']
    creator_id = order.get('creator_id')
    if creator_id != None:
        new_order = Order(sender_pk=sender_pk, receiver_pk=receiver_pk, buy_ccy=buy_currency, sell_ccy=sell_currency, buy_amt=buy_amount, sell_amt=sell_amount, creator_id=creator_id)
    else:
        new_order = Order(sender_pk=sender_pk, receiver_pk=receiver_pk, buy_ccy=buy_currency, sell_ccy=sell_currency, buy_amt=buy_amount, sell_amt=sell_amount)
    
    session.add(new_order)
    session.commit()
    old_orders = session.query(Order).filter(Order.filled == None).all()

    for old_order in old_orders:
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
