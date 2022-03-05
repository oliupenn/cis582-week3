from flask import Flask, request, jsonify
from flask_restful import Api
import json
import eth_account
import algosdk

app = Flask(__name__)
api = Api(app)
app.url_map.strict_slashes = False


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    content = request.get_json(silent=True)
    if content == None:
        return jsonify("No json data is sent.")
    sig = content.get('sig')
    payload = content.get('payload')
    message = payload.get('message')
    pk = payload.get('pk')
    platform = payload.get('platform')
    
    # Check if signature is valid

    if platform == 'Ethereum':
        eth_account.Account.enable_unaudited_hdwallet_features()
        acct, mnemonic = eth_account.Account.create_with_mnemonic()

        eth_pk = acct.address
        eth_sk = acct.key

        eth_encoded_msg = eth_account.messages.encode_defunct(text=json.dumps(payload))
        eth_sig_obj = eth_account.Account.sign_message(eth_encoded_msg, eth_sk)

        if eth_account.Account.recover_message(eth_encoded_msg, signature=eth_sig_obj.signature.hex()) == eth_pk:
            result = True
        else:
            result = False

    elif platform == 'Algorand':
        algo_sk, algo_pk = algosdk.account.generate_account()
        algo_sig_str = algosdk.util.sign_bytes(json.dumps(payload).encode('utf-8'), algo_sk)

        if algosdk.util.verify_bytes(json.dumps(payload).encode('utf-8'), algo_sig_str, algo_pk):
            result = True
        else:
            result = False

    return jsonify(result)


if __name__ == '__main__':
    app.run(port='5002')
