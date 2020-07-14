import pytest
import asyncio
from decimal import Decimal
from secrets import token_bytes
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
    async def wallet_node(self):
        async for _ in setup_simulators_and_wallets(1, 1, {}):
            yield _

    @pytest.fixture(scope="function")
    async def two_wallet_nodes(self):
        async for _ in setup_simulators_and_wallets(
            1, 2, {"COINBASE_FREEZE_PERIOD": 0}
        ):
            yield _

    @pytest.fixture(scope="function")
    async def two_wallet_nodes_five_freeze(self):
        async for _ in setup_simulators_and_wallets(
            1, 2, {"COINBASE_FREEZE_PERIOD": 5}
        ):
            yield _

    @pytest.fixture(scope="function")
    async def three_sim_two_wallets(self):
        async for _ in setup_simulators_and_wallets(
            3, 2, {"COINBASE_FREEZE_PERIOD": 0}
        ):
            yield _

    @pytest.mark.asyncio
    async def test_wallet_coinbase(self, wallet_node):
        num_blocks = 10
        full_nodes, wallets = wallet_node
        full_node_1, server_1 = full_nodes[0]
        wallet_node, server_2 = wallets[0]
        wallet = wallet_node.wallet_state_manager.main_wallet

        escrow_wallet: RecoverableWallet = await RecoverableWallet.create(
            wallet_node.wallet_state_manager,
            Decimal('1.1'),
            1,
            DurationType.BLOCKS
        )

        ph = await escrow_wallet.get_new_puzzlehash()

        await server_2.start_client(PeerInfo("localhost", uint16(server_1._port)), None)
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))

        await asyncio.sleep(3)
        funds = sum(
            [
                calculate_base_fee(uint32(i)) + calculate_block_reward(uint32(i))
                for i in range(1, num_blocks - 2)
            ]
        )
        assert await escrow_wallet.get_confirmed_balance() == funds

    @pytest.mark.asyncio
    async def test_wallet_make_transaction(self, two_wallet_nodes):
        num_blocks = 10
        full_nodes, wallets = two_wallet_nodes
        full_node_1, server_1 = full_nodes[0]
        wallet_node, server_2 = wallets[0]
        wallet_node_2, server_3 = wallets[1]
        wallet = wallet_node.wallet_state_manager.main_wallet

        escrow_wallet: RecoverableWallet = await RecoverableWallet.create(
            wallet_node.wallet_state_manager,
            Decimal('1.1'),
            1,
            DurationType.BLOCKS
        )

        ph = await escrow_wallet.get_new_puzzlehash()

        await server_2.start_client(PeerInfo("localhost", uint16(server_1._port)), None)

        for i in range(0, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))

        funds = sum(
            [
                calculate_base_fee(uint32(i)) + calculate_block_reward(uint32(i))
                for i in range(1, num_blocks - 1)
            ]
        )

        await asyncio.sleep(2)

        assert await escrow_wallet.get_confirmed_balance() == funds
        assert await escrow_wallet.get_unconfirmed_balance() == funds
        assert await escrow_wallet.get_unconfirmed_spendable() == funds

        tx = await escrow_wallet.generate_signed_transaction(
                10,
                await wallet_node_2.wallet_state_manager.main_wallet.get_new_puzzlehash()
        )
        await escrow_wallet.push_transaction(tx)

        await asyncio.sleep(2)
        confirmed_balance = await escrow_wallet.get_confirmed_balance()
        unconfirmed_balance = await escrow_wallet.get_unconfirmed_balance()

        assert confirmed_balance == funds
        assert unconfirmed_balance == funds - 10

        for i in range(0, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))

        await asyncio.sleep(2)

        new_funds = sum(
            [
                calculate_base_fee(uint32(i)) + calculate_block_reward(uint32(i))
                for i in range(1, (2 * num_blocks) - 1)
            ]
        )

        confirmed_balance = await escrow_wallet.get_confirmed_balance()
        unconfirmed_balance = await escrow_wallet.get_unconfirmed_balance()

        assert confirmed_balance == new_funds - 10
        assert unconfirmed_balance == new_funds - 10

    @pytest.mark.asyncio
    async def test_wallet_coinbase_reorg(self, wallet_node):
        num_blocks = 10
        full_nodes, wallets = wallet_node
        full_node_1, server_1 = full_nodes[0]
        wallet_node, server_2 = wallets[0]
        wallet: RecoverableWallet = await RecoverableWallet.create(
            wallet_node.wallet_state_manager,
            Decimal('1.1'),
            1,
            DurationType.BLOCKS
        )

        ph = await wallet.get_new_puzzlehash()

        await server_2.start_client(PeerInfo("localhost", uint16(server_1._port)), None)
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))

        await asyncio.sleep(3)
        funds = sum(
            [
                calculate_base_fee(uint32(i)) + calculate_block_reward(uint32(i))
                for i in range(1, num_blocks - 2)
            ]
        )
        assert await wallet.get_confirmed_balance() == funds

        await full_node_1.reorg_from_index_to_new_index(
            ReorgProtocol(uint32(5), uint32(num_blocks + 3), token_bytes())
        )
        await asyncio.sleep(3)

        funds = sum(
            [
                calculate_base_fee(uint32(i)) + calculate_block_reward(uint32(i))
                for i in range(1, 5)
            ]
        )

        assert await wallet.get_confirmed_balance() == funds
