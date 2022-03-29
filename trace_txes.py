from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import json
from datetime import datetime

rpc_user='quaker_quorum'
rpc_password='franklin_fought_for_continental_cash'
rpc_ip='3.134.159.30'
rpc_port='8332'

rpc_connection = AuthServiceProxy("http://%s:%s@%s:%s"%(rpc_user, rpc_password, rpc_ip, rpc_port))

###################################

class TXO:
    def __init__(self, tx_hash, n, amount, owner, time ):
        self.tx_hash = tx_hash 
        self.n = n
        self.amount = amount
        self.owner = owner
        self.time = time
        self.inputs = []

    def __str__(self, level=0):
        ret = "\t"*level+repr(self.tx_hash)+"\n"
        for tx in self.inputs:
            ret += tx.__str__(level+1)
        return ret

    def to_json(self):
        fields = ['tx_hash','n','amount','owner']
        json_dict = { field: self.__dict__[field] for field in fields }
        json_dict.update( {'time': datetime.timestamp(self.time) } )
        if len(self.inputs) > 0:
            for txo in self.inputs:
                json_dict.update( {'inputs': json.loads(txo.to_json()) } )
        return json.dumps(json_dict, sort_keys=True, indent=4)

    @classmethod
    def from_tx_hash(cls,tx_hash,n=0):
        tx = rpc_connection.getrawtransaction(tx_hash,True)
        hash = tx.get('hash')
        vout = tx.get('vout')[n]
        amount = int(vout.get('value') * 100000000)
        public_key = vout.get('scriptPubKey')
        addresses = public_key.get('addresses')
        owner = addresses[0]
        time = tx.get('time')
        time = datetime.fromtimestamp(time)
        return cls(tx_hash,n,amount,owner,time)
        #YOUR CODE HERE

    def get_inputs(self,d=1):
        tx = rpc_connection.getrawtransaction(self.tx_hash, True)
        vin = tx.get('vin')
        print(self.inputs)
        for i in vin:
            txid = i.get('txid')
            self.inputs.append(TXO.from_tx_hash(txid))
            print(self.inputs)
        if d == 2:
            for input in self.inputs:
                input.get_inputs()
