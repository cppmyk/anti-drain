from eth_account.datastructures import SignedTransaction
from eth_typing import ChecksumAddress, BlockNumber
from flashbots import flashbot
from web3 import Web3, HTTPProvider
from eth_account.account import Account
from eth_account.signers.local import LocalAccount
from web3.contract import Contract
from web3.exceptions import TransactionNotFound
from web3.types import TxParams, Wei

from erc20_abi import ERC20_ABI

RESCUER_KEY: str = ""
COMPROMISED_KEY: str = ""
FLASHBOTS_KEY: str = ""

ETH_CHAIN_ID: int = 1
ETH_HTTP_URL: str = 'https://eth.llamarpc.com'

WETH_CONTRACT_ADDRESS: ChecksumAddress = Web3.to_checksum_address('0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2')
WETH_TRANSFER_GAS_LIMIT: int = 100000
ETH_TRANSFER_GAS_LIMIT: int = 21000

WETH_AMOUNT_TO_RESCUE: Wei = Web3.to_wei(0.001, 'ether')

rescuer: LocalAccount = Account.from_key(RESCUER_KEY)
compromised: LocalAccount = Account.from_key(COMPROMISED_KEY)
signer: LocalAccount = Account.from_key(FLASHBOTS_KEY)

w3: Web3 = Web3(HTTPProvider(ETH_HTTP_URL))
flashbot(w3, signer)


def build_erc20_transfer_transaction(sender_address: ChecksumAddress, destination_address: ChecksumAddress,
                                     amount: Wei, gas_price: Wei, nonce: int) -> TxParams:
    contract: Contract = w3.eth.contract(address=WETH_CONTRACT_ADDRESS, abi=ERC20_ABI)

    tx: TxParams = contract.functions.transfer(destination_address, amount).build_transaction(
        {
            'from': sender_address,
            'gas': WETH_TRANSFER_GAS_LIMIT,
            'gasPrice': gas_price,
            'nonce': nonce
        }
    )

    return tx


def build_send_transaction(destination_address: ChecksumAddress, amount: Wei, gas_price: Wei, nonce: int) -> TxParams:
    tx: TxParams = {
        'to': destination_address,
        'value': amount,
        'gas': ETH_TRANSFER_GAS_LIMIT,
        'gasPrice': gas_price,
        'nonce': nonce,
        'chainId': ETH_CHAIN_ID
    }

    return tx


def main():
    print(f'Rescuer address: {rescuer.address}')
    print(f'Compromised address: {compromised.address}')
    print('-' * 100)

    gas_price: Wei = Wei(int(w3.eth.gas_price))
    eth_to_cover_transfer: Wei = Wei(gas_price * WETH_TRANSFER_GAS_LIMIT)

    rescuer_nonce: int = w3.eth.get_transaction_count(rescuer.address)
    deposit_tx: TxParams = build_send_transaction(compromised.address, eth_to_cover_transfer, gas_price, rescuer_nonce)
    deposit_tx_signed: SignedTransaction = rescuer.sign_transaction(deposit_tx)

    compromised_nonce: int = w3.eth.get_transaction_count(compromised.address)
    weth_transfer_tx: TxParams = build_erc20_transfer_transaction(compromised.address, rescuer.address,
                                                                  WETH_AMOUNT_TO_RESCUE, gas_price, compromised_nonce)
    weth_transfer_tx_signed: SignedTransaction = compromised.sign_transaction(weth_transfer_tx)

    bundle = [
        {'signed_transaction': deposit_tx_signed.rawTransaction},
        {'signed_transaction': weth_transfer_tx_signed.rawTransaction},
    ]

    while True:
        block: BlockNumber = w3.eth.block_number

        print(f'Simulating on block {block}')
        try:
            w3.flashbots.simulate(bundle, block)
            print('Simulation successful.')
        except Exception as e:
            print("Simulation error", e)

        print(f"Sending bundle targeting block {block + 1}")

        send_result = w3.flashbots.send_bundle(
            bundle,
            target_block_number=block + 1
        )
        print("bundleHash", w3.toHex(send_result.bundle_hash()))

        stats = w3.flashbots.get_bundle_stats_v2(
            w3.toHex(send_result.bundle_hash()), block
        )
        print("bundleStats", stats)

        try:
            receipts = send_result.receipts()
            print(f"Bundle was mined in block {receipts[0].blockNumber}")
            break
        except TransactionNotFound:
            print(f"Bundle not found in block {block + 1}")
        print('-' * 100)

    print('Finished')


if __name__ == "__main__":
    main()
