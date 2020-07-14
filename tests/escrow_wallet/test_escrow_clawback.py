import asyncio
import pytest
from decimal import Decimal
from src.simulator.simulator_protocol import FarmNewBlockProtocol, ReorgProtocol
from src.types.peer_info import PeerInfo
from src.util.ints import uint16, uint32
from tests.setup_nodes import setup_simulators_and_wallets
from src.consensus.block_rewards import calculate_base_fee, calculate_block_reward
from src.wallet.escrow_wallet.recoverable_wallet import RecoverableWallet, DurationType, ProgramHash


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.get_event_loop()
    yield loop


class TestWalletSimulator:
    @pytest.fixture(scope="function")
    async def three_wallet_nodes(self):
        async for _ in setup_simulators_and_wallets(
            1, 3, {"COINBASE_FREEZE_PERIOD": 0}
        ):
            yield _

    @pytest.mark.asyncio
    async def test_wallet_recovery(self, three_wallet_nodes):
        num_blocks = 10
        full_nodes, wallets = three_wallet_nodes
        full_node, server_1 = full_nodes[0]
        wallet_node_0, server_2 = wallets[0]
        wallet_node_1, server_3 = wallets[1]
        wallet_node_2, server_4 = wallets[2]
        farmer_wallet = wallet_node_2.wallet_state_manager.main_wallet

        # generate target escrow wallet
        escrow_wallet_0: RecoverableWallet = await RecoverableWallet.create(
            wallet_node_0.wallet_state_manager,
            Decimal('1.1'),
            1,
            DurationType.BLOCKS
        )

        # put funds in lost wallet
        ph = await escrow_wallet_0.get_new_puzzlehash()
        await server_2.start_client(PeerInfo("localhost", uint16(server_1._port)), None)
        await full_node.farm_new_block(FarmNewBlockProtocol(ph))
        ph = await farmer_wallet.get_new_puzzlehash()
        for i in range(5):
            await full_node.farm_new_block(FarmNewBlockProtocol(ph))

        lost_funds = calculate_base_fee(uint32(1)) + calculate_block_reward(uint32(1))

        await asyncio.sleep(2)
        assert await escrow_wallet_0.get_confirmed_balance() == lost_funds
        assert await escrow_wallet_0.get_unconfirmed_balance() == lost_funds
        assert await escrow_wallet_0.get_unconfirmed_spendable() == lost_funds

        # save target wallet's backup string
        backup_string = escrow_wallet_0.get_backup_string()

        # generate escrow wallet to perform attempted attack
        escrow_wallet_1: RecoverableWallet = await RecoverableWallet.create(
            wallet_node_1.wallet_state_manager,
            Decimal('1.1'),
            1,
            DurationType.BLOCKS
        )

        # add funds to attacker wallet to cover the stake
        ph = await escrow_wallet_1.get_new_puzzlehash()
        await server_3.start_client(PeerInfo("localhost", uint16(server_1._port)), None)
        await full_node.farm_new_block(FarmNewBlockProtocol(ph))
        ph = await farmer_wallet.get_new_puzzlehash()
        for i in range(5):
            await full_node.farm_new_block(FarmNewBlockProtocol(ph))
        funds = calculate_base_fee(uint32(1)) + calculate_block_reward(uint32(1))
        await asyncio.sleep(2)
        assert await escrow_wallet_1.get_confirmed_balance() == funds
        assert await escrow_wallet_1.get_unconfirmed_balance() == funds
        assert await escrow_wallet_1.get_unconfirmed_spendable() == funds
        print(await escrow_wallet_1.get_confirmed_balance())

        # send transaction to restore target wallets coins to escrow
        await escrow_wallet_1.restore(backup_string, full_node)

        # commit transaction
        ph = await farmer_wallet.get_new_puzzlehash()
        for i in range(0, num_blocks):
            await full_node.farm_new_block(FarmNewBlockProtocol(ph))
            print(await escrow_wallet_1.get_confirmed_balance())

        assert await escrow_wallet_1.get_confirmed_balance() == funds - 0.1 * lost_funds

        coin_records = await full_node.coin_store.get_unspent_coin_records()
        unspent_coins = [coin_record.coin for coin_record in coin_records]
        for recovery_string in escrow_wallet_1.escrow_coins:
            for coin in escrow_wallet_1.escrow_coins[recovery_string]:
                assert coin in unspent_coins

        # find coins moved to escrow
        clawback_coins = [coin for coin in unspent_coins if escrow_wallet_0.is_in_escrow(coin)]
        assert(len(clawback_coins) != 0)

        # send clawback transaction
        await escrow_wallet_0.clawback(clawback_coins)

        # commit transaction
        ph = await farmer_wallet.get_new_puzzlehash()
        for i in range(0, num_blocks):
            await full_node.farm_new_block(FarmNewBlockProtocol(ph))
            print(await escrow_wallet_1.get_confirmed_balance())

        assert await escrow_wallet_1.get_confirmed_balance() == funds - 0.1 * lost_funds
        assert await escrow_wallet_0.get_confirmed_balance() == funds + 0.1 * lost_funds
