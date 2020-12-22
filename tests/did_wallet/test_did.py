import asyncio
import time
import clvm
import pytest
from src.simulator.simulator_protocol import FarmNewBlockProtocol
from src.types.peer_info import PeerInfo
from src.util.ints import uint16, uint32, uint64
from tests.setup_nodes import setup_simulators_and_wallets
from src.consensus.block_rewards import calculate_pool_reward, calculate_base_farmer_reward
from src.wallet.did_wallet.did_wallet import DIDWallet
from src.wallet.did_wallet import did_wallet_puzzles
from clvm_tools import binutils
from src.types.program import Program
from src.wallet.derivation_record import DerivationRecord
from src.types.coin_solution import CoinSolution
from blspy import AugSchemeMPL
from src.types.spend_bundle import SpendBundle
from src.wallet.transaction_record import TransactionRecord
from src.wallet.derive_keys import master_sk_to_wallet_sk


def calculate_base_fee(*args):
    return uint64(2000000000000)


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.get_event_loop()
    yield loop


class TestDIDWallet:
    @pytest.fixture(scope="function")
    async def wallet_node(self):
        async for _ in setup_simulators_and_wallets(1, 1, {}):
            yield _

    @pytest.fixture(scope="function")
    async def two_wallet_nodes(self):
        async for _ in setup_simulators_and_wallets(1, 2, {}):
            yield _

    @pytest.fixture(scope="function")
    async def two_wallet_nodes_five_freeze(self):
        async for _ in setup_simulators_and_wallets(1, 2, {}):
            yield _

    @pytest.fixture(scope="function")
    async def three_sim_two_wallets(self):
        async for _ in setup_simulators_and_wallets(3, 2, {}):
            yield _

    async def time_out_assert(self, timeout: int, function, value, arg=None):
        start = time.time()
        while time.time() - start < timeout:
            if arg is None:
                function_result = await function()
            else:
                function_result = await function(arg)
            if value == function_result:
                return
            await asyncio.sleep(1)
        assert False

    @pytest.mark.asyncio
    async def test_creation_from_backup_file(self, two_wallet_nodes):
        num_blocks = 10
        full_nodes, wallets = two_wallet_nodes
        full_node_api = full_nodes[0]
        server_1 = full_node_api.full_node.server
        wallet_node, server_2 = wallets[0]
        wallet_node_2, server_3 = wallets[1]
        wallet = wallet_node.wallet_state_manager.main_wallet
        wallet2 = wallet_node_2.wallet_state_manager.main_wallet

        await server_2.start_client(PeerInfo("localhost", uint16(server_1._port)), None)
        await server_3.start_client(PeerInfo("localhost", uint16(server_1._port)), None)

        ph = await wallet.get_new_puzzlehash()

        await server_2.start_client(PeerInfo("localhost", uint16(server_1._port)), None)

        for i in range(0, num_blocks):
            await full_node_api.farm_new_block(FarmNewBlockProtocol(ph))

        funds = sum(
            [
                calculate_pool_reward(uint32(i + 1)) + calculate_base_farmer_reward(uint32(i + 1))
                for i in range(0, num_blocks - 1)
            ]
        )

        await self.time_out_assert(5, wallet.get_confirmed_balance, funds)
        await self.time_out_assert(5, wallet.get_unconfirmed_balance, funds)
        # Wallet1 sets up DIDWallet1 without any backup set
        did_wallet: DIDWallet = await DIDWallet.create_new_did_wallet(
            wallet_node.wallet_state_manager, wallet, uint64(100)
        )

        for i in range(0, num_blocks):
            await full_node_api.farm_new_block(FarmNewBlockProtocol(ph))

        await self.time_out_assert(15, did_wallet.get_confirmed_balance, 100)
        await self.time_out_assert(15, did_wallet.get_unconfirmed_balance, 100)
        await self.time_out_assert(15, did_wallet.get_pending_change_balance, 0)
        # Wallet1 sets up DIDWallet2 with DIDWallet1 as backup
        backup_ids = [bytes.fromhex(did_wallet.get_my_DID())]
        did_wallet_2: DIDWallet = await DIDWallet.create_new_did_wallet(
            wallet_node.wallet_state_manager, wallet, uint64(200), backup_ids
        )

        for i in range(1, num_blocks):
            await full_node_api.farm_new_block(FarmNewBlockProtocol(ph))

        await self.time_out_assert(15, did_wallet_2.get_confirmed_balance, 200)
        await self.time_out_assert(15, did_wallet_2.get_unconfirmed_balance, 200)
        await self.time_out_assert(15, did_wallet_2.get_pending_change_balance, 0)

        filename = "test.backup"
        did_wallet_2.create_backup(filename)

        # Wallet2 recovers DIDWallet2 to a new set of keys
        did_wallet_3 = await DIDWallet.create_new_did_wallet_from_recovery(
            wallet_node_2.wallet_state_manager, wallet2, filename
        )
        coins = await did_wallet_2.select_coins(1)
        coin = coins.copy().pop()
        assert did_wallet_3.did_info.temp_coin == coin
        info = await did_wallet.get_info_for_recovery()
        parent_innerpuzhash_amounts_for_recovery_ids = [info]
        newpuz = await did_wallet_3.get_new_puzzle()
        newpuzhash = newpuz.get_tree_hash()
        pubkey = bytes(
            (
                await did_wallet_3.wallet_state_manager.get_unused_derivation_record(
                    did_wallet_3.wallet_info.id
                )
            ).pubkey
        )
        message_spend_bundle = await did_wallet.create_attestment(
            did_wallet_3.did_info.temp_coin.name(), newpuzhash, pubkey
        )
        await did_wallet_3.recovery_spend(
            did_wallet_3.did_info.temp_coin,
            newpuzhash,
            parent_innerpuzhash_amounts_for_recovery_ids,
            pubkey,
            message_spend_bundle,
        )

        for i in range(1, num_blocks):
            await full_node_api.farm_new_block(FarmNewBlockProtocol(ph))

        await self.time_out_assert(15, did_wallet_3.get_confirmed_balance, 200)
        await self.time_out_assert(15, did_wallet_3.get_unconfirmed_balance, 200)

        # DIDWallet3 spends the money back to itself
        ph2 = await wallet2.get_new_puzzlehash()
        await did_wallet_3.create_spend(ph2)

        for i in range(1, num_blocks):
            await full_node_api.farm_new_block(FarmNewBlockProtocol(ph))

        await self.time_out_assert(15, wallet2.get_confirmed_balance, 200)
        await self.time_out_assert(15, wallet2.get_unconfirmed_balance, 200)

    @pytest.mark.asyncio
    async def test_did_recovery_with_multiple_backup_dids(self, two_wallet_nodes):
        num_blocks = 5
        full_nodes, wallets = two_wallet_nodes
        full_node_1 = full_nodes[0]
        server_1 = full_node_1.full_node.server
        wallet_node, server_2 = wallets[0]
        wallet_node_2, server_3 = wallets[1]
        wallet = wallet_node.wallet_state_manager.main_wallet
        wallet2 = wallet_node_2.wallet_state_manager.main_wallet

        ph2 = await wallet.get_new_puzzlehash()

        await server_2.start_client(PeerInfo("localhost", uint16(server_1._port)), None)
        await server_3.start_client(PeerInfo("localhost", uint16(server_1._port)), None)
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph2))

        funds = sum(
            [
                calculate_pool_reward(uint32(i)) + calculate_base_farmer_reward(uint32(i))
                for i in range(1, num_blocks - 1)
            ]
        )

        await self.time_out_assert(15, wallet.get_confirmed_balance, funds)

        did_wallet: DIDWallet = await DIDWallet.create_new_did_wallet(
            wallet_node.wallet_state_manager, wallet, uint64(100)
        )

        ph = await wallet2.get_new_puzzlehash()
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))

        await self.time_out_assert(15, did_wallet.get_confirmed_balance, 100)
        await self.time_out_assert(15, did_wallet.get_unconfirmed_balance, 100)

        recovery_list = [bytes.fromhex(did_wallet.get_my_DID())]

        did_wallet_2: DIDWallet = await DIDWallet.create_new_did_wallet(
            wallet_node_2.wallet_state_manager, wallet2, uint64(100), recovery_list
        )

        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))

        assert did_wallet_2.did_info.backup_ids == recovery_list

        recovery_list.append(bytes.fromhex(did_wallet_2.get_my_DID()))

        did_wallet_3: DIDWallet = await DIDWallet.create_new_did_wallet(
            wallet_node_2.wallet_state_manager, wallet2, uint64(200), recovery_list
        )
        ph2 = await wallet.get_new_puzzlehash()
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph2))

        assert did_wallet_3.did_info.backup_ids == recovery_list

        coins = await did_wallet_3.select_coins(1)
        coin = coins.pop()
        info1 = await did_wallet.get_info_for_recovery()
        info2 = await did_wallet_2.get_info_for_recovery()
        pubkey = (
            await did_wallet_2.wallet_state_manager.get_unused_derivation_record(
                did_wallet_2.wallet_info.id
            )
        ).pubkey
        message_spend_bundle = await did_wallet.create_attestment(
            coin.name(), ph, pubkey
        )
        message_spend_bundle2 = await did_wallet_2.create_attestment(
            coin.name(), ph, pubkey
        )
        message_spend_bundle = message_spend_bundle.aggregate(
            [message_spend_bundle, message_spend_bundle2]
        )
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph2))
        info = Program.to([info1, info2])

        await did_wallet_3.recovery_spend(coin, ph, info, pubkey, message_spend_bundle)

        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph2))
        await self.time_out_assert(15, wallet2.get_confirmed_balance, 287999999999900)
        await self.time_out_assert(15, wallet2.get_unconfirmed_balance, 287999999999900)
        await self.time_out_assert(15, did_wallet_3.get_confirmed_balance, 0)
        await self.time_out_assert(15, did_wallet_3.get_unconfirmed_balance, 0)

    @pytest.mark.asyncio
    async def test_did_recovery_with_empty_set(self, two_wallet_nodes):
        num_blocks = 5
        full_nodes, wallets = two_wallet_nodes
        full_node_1 = full_nodes[0]
        wallet_node, server_2 = wallets[0]
        wallet_node_2, server_3 = wallets[1]
        wallet = wallet_node.wallet_state_manager.main_wallet
        wallet2 = wallet_node_2.wallet_state_manager.main_wallet

        ph = await wallet.get_new_puzzlehash()

        await server_2.start_client(PeerInfo("localhost", uint16(full_node_1.full_node.server._port)), None)
        await server_3.start_client(PeerInfo("localhost", uint16(full_node_1.full_node.server._port)), None)
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))

        funds = sum(
            [
                calculate_pool_reward(uint32(i)) + calculate_base_farmer_reward(uint32(i))
                for i in range(1, num_blocks - 1)
            ]
        )

        await self.time_out_assert(15, wallet.get_confirmed_balance, funds)

        did_wallet: DIDWallet = await DIDWallet.create_new_did_wallet(
            wallet_node.wallet_state_manager, wallet, uint64(100)
        )

        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))

        await self.time_out_assert(15, did_wallet.get_confirmed_balance, 100)
        await self.time_out_assert(15, did_wallet.get_unconfirmed_balance, 100)
        coins = await did_wallet.select_coins(1)
        coin = coins.pop()
        info = Program.to([])
        pubkey = (
            await did_wallet.wallet_state_manager.get_unused_derivation_record(
                did_wallet.wallet_info.id
            )
        ).pubkey
        spend_bundle = await did_wallet.recovery_spend(
            coin, ph, info, pubkey, SpendBundle([], AugSchemeMPL.aggregate([]))
        )
        additions = spend_bundle.additions()
        assert additions == []

    @pytest.mark.asyncio
    async def test_did_attest_after_recovery(self, two_wallet_nodes):
        num_blocks = 5
        full_nodes, wallets = two_wallet_nodes
        full_node_1 = full_nodes[0]
        wallet_node, server_2 = wallets[0]
        wallet_node_2, server_3 = wallets[1]
        wallet = wallet_node.wallet_state_manager.main_wallet
        wallet2 = wallet_node_2.wallet_state_manager.main_wallet
        ph = await wallet.get_new_puzzlehash()

        await server_2.start_client(PeerInfo("localhost", uint16(full_node_1.full_node.server._port)), None)
        await server_3.start_client(PeerInfo("localhost", uint16(full_node_1.full_node.server._port)), None)
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))

        funds = sum(
            [
                calculate_pool_reward(uint32(i)) + calculate_base_farmer_reward(uint32(i))
                for i in range(1, num_blocks - 1)
            ]
        )

        await self.time_out_assert(15, wallet.get_confirmed_balance, funds)

        did_wallet: DIDWallet = await DIDWallet.create_new_did_wallet(
            wallet_node.wallet_state_manager, wallet, uint64(100)
        )

        ph2 = await wallet2.get_new_puzzlehash()
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph2))

        await self.time_out_assert(15, did_wallet.get_confirmed_balance, 100)
        await self.time_out_assert(15, did_wallet.get_unconfirmed_balance, 100)
        recovery_list = [bytes.fromhex(did_wallet.get_my_DID())]

        did_wallet_2: DIDWallet = await DIDWallet.create_new_did_wallet(
            wallet_node_2.wallet_state_manager, wallet2, uint64(100), recovery_list
        )
        ph = await wallet.get_new_puzzlehash()
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))
        await self.time_out_assert(15, did_wallet_2.get_confirmed_balance, 100)
        await self.time_out_assert(15, did_wallet_2.get_unconfirmed_balance, 100)
        assert did_wallet_2.did_info.backup_ids == recovery_list

        # Update coin with new ID info
        recovery_list = [bytes.fromhex(did_wallet_2.get_my_DID())]
        await did_wallet.update_recovery_list(recovery_list, uint64(1))
        assert did_wallet.did_info.backup_ids == recovery_list
        updated_puz = await did_wallet.get_new_puzzle()
        await did_wallet.create_spend(updated_puz.get_tree_hash())

        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph2))

        await self.time_out_assert(15, did_wallet.get_confirmed_balance, 100)
        await self.time_out_assert(15, did_wallet.get_unconfirmed_balance, 100)

        # DID Wallet 2 recovers into itself with new innerpuz
        new_puz = await did_wallet_2.get_new_puzzle()
        new_ph = new_puz.get_tree_hash()
        coins = await did_wallet_2.select_coins(1)
        coin = coins.pop()
        info = await did_wallet.get_info_for_recovery()
        pubkey = (
            await did_wallet_2.wallet_state_manager.get_unused_derivation_record(
                did_wallet_2.wallet_info.id
            )
        ).pubkey
        message_spend_bundle = await did_wallet.create_attestment(
            coin.name(), new_ph, pubkey
        )
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph2))

        info = Program.to([info])
        await did_wallet_2.recovery_spend(
            coin, new_ph, info, pubkey, message_spend_bundle
        )

        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))

        await self.time_out_assert(15, did_wallet_2.get_confirmed_balance, 100)
        await self.time_out_assert(15, did_wallet_2.get_unconfirmed_balance, 100)

        # Recovery spend
        coins = await did_wallet.select_coins(1)
        coin = coins.pop()
        info = await did_wallet_2.get_info_for_recovery()
        pubkey = (
            await did_wallet.wallet_state_manager.get_unused_derivation_record(
                did_wallet.wallet_info.id
            )
        ).pubkey
        message_spend_bundle = await did_wallet_2.create_attestment(
            coin.name(), ph, pubkey
        )
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph2))
        info = [info]

        await did_wallet.recovery_spend(coin, ph, info, pubkey, message_spend_bundle)

        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))

        await self.time_out_assert(15, wallet.get_confirmed_balance, 544000000000000)
        await self.time_out_assert(15, wallet.get_unconfirmed_balance, 544000000000000)
        await self.time_out_assert(15, did_wallet.get_confirmed_balance, 0)
        await self.time_out_assert(15, did_wallet.get_unconfirmed_balance, 0)

    @pytest.mark.asyncio
    async def test_make_double_output(self, two_wallet_nodes):
        num_blocks = 5
        full_nodes, wallets = two_wallet_nodes
        full_node_1 = full_nodes[0]
        wallet_node, server_2 = wallets[0]
        wallet_node_2, server_3 = wallets[1]
        wallet = wallet_node.wallet_state_manager.main_wallet
        wallet2 = wallet_node_2.wallet_state_manager.main_wallet
        ph = await wallet.get_new_puzzlehash()

        await server_2.start_client(PeerInfo("localhost", uint16(full_node_1.full_node.server._port)), None)
        await server_3.start_client(PeerInfo("localhost", uint16(full_node_1.full_node.server._port)), None)
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))

        funds = sum(
            [
                calculate_pool_reward(uint32(i)) + calculate_base_farmer_reward(uint32(i))
                for i in range(1, num_blocks - 1)
            ]
        )

        await self.time_out_assert(15, wallet.get_confirmed_balance, funds)

        did_wallet: DIDWallet = await DIDWallet.create_new_did_wallet(
            wallet_node.wallet_state_manager, wallet, uint64(100)
        )
        ph2 = await wallet2.get_new_puzzlehash()
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph2))

        # Lock up with non DID innerpuz so that we can create two outputs
        # Innerpuz will output the innersol, so we just pass in ((51 0xMyPuz 49) (51 0xMyPuz 51))
        innerpuz = Program(binutils.assemble("1"))
        innerpuzhash = innerpuz.get_tree_hash()

        puz = did_wallet_puzzles.create_fullpuz(
            innerpuzhash,
            did_wallet.did_info.my_did,
        )

        # Add the hacked puzzle to the puzzle store so that it is recognised as "our" puzzle
        old_devrec = await did_wallet.wallet_state_manager.get_unused_derivation_record(
            did_wallet.wallet_info.id
        )
        devrec = DerivationRecord(
            old_devrec.index,
            puz.get_tree_hash(),
            old_devrec.pubkey,
            old_devrec.wallet_type,
            old_devrec.wallet_id,
        )
        await did_wallet.wallet_state_manager.puzzle_store.add_derivation_paths(
            [devrec]
        )
        await did_wallet.create_spend(puz.get_tree_hash())

        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph2))

        await self.time_out_assert(15, did_wallet.get_confirmed_balance, 100)
        await self.time_out_assert(15, did_wallet.get_unconfirmed_balance, 100)

        # Create spend by hand so that we can use the weird innersol
        coins = await did_wallet.select_coins(1)
        coin = coins.pop()
        # innerpuz is our desired output
        innersol = Program.to([[51, coin.puzzle_hash, 45], [51, coin.puzzle_hash, 55]])
        # full solution is (corehash parent_info my_amount innerpuz_reveal solution)
        parent_info = await did_wallet.get_parent_for_coin(coin)
        fullsol = Program.to(
            [
                [
                    parent_info.parent_name,
                    parent_info.inner_puzzle_hash,
                    parent_info.amount,
                ],
                coin.amount,
                innersol,
            ]
        )
        try:
            cost, result = puz.run_with_cost(fullsol)
        except Exception as e:
            assert e.args == ("clvm raise",)
        else:
            assert False

    @pytest.mark.asyncio
    async def test_make_fake_coin(self, two_wallet_nodes):
        num_blocks = 5
        full_nodes, wallets = two_wallet_nodes
        full_node_1 = full_nodes[0]
        wallet_node, server_2 = wallets[0]
        wallet_node_2, server_3 = wallets[1]
        wallet = wallet_node.wallet_state_manager.main_wallet
        wallet2 = wallet_node_2.wallet_state_manager.main_wallet
        await server_2.start_client(PeerInfo("localhost", uint16(full_node_1.full_node.server._port)), None)
        await server_3.start_client(PeerInfo("localhost", uint16(full_node_1.full_node.server._port)), None)
        ph = await wallet.get_new_puzzlehash()

        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))

        funds = sum(
            [
                calculate_pool_reward(uint32(i)) + calculate_base_farmer_reward(uint32(i))
                for i in range(1, num_blocks - 1)
            ]
        )

        await self.time_out_assert(15, wallet.get_confirmed_balance, funds)

        did_wallet: DIDWallet = await DIDWallet.create_new_did_wallet(
            wallet_node.wallet_state_manager, wallet, uint64(100)
        )
        ph2 = await wallet2.get_new_puzzlehash()
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph2))
        coins = await did_wallet.select_coins(1)
        coin = coins.pop()

        # copy info for later
        parent_info = await did_wallet.get_parent_for_coin(coin)
        id_puzhash = coin.puzzle_hash

        await did_wallet.create_spend(ph)
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))
        await self.time_out_assert(15, did_wallet.get_confirmed_balance, 0)
        await self.time_out_assert(15, did_wallet.get_unconfirmed_balance, 0)

        tx_record = await wallet.generate_signed_transaction(100, id_puzhash)
        await wallet.push_transaction(tx_record)

        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph))

        await self.time_out_assert(15, wallet.get_confirmed_balance, 399999999999900)
        await self.time_out_assert(15, wallet.get_unconfirmed_balance, 399999999999900)

        coins = await did_wallet.select_coins(1)
        assert len(coins) >= 1

        coin = coins.pop()

        # Write spend by hand
        # innerpuz solution is (mode amount new_puz identity my_puz)
        innersol = Program.to([0, coin.amount, ph, coin.name(), coin.puzzle_hash])
        # full solution is (corehash parent_info my_amount innerpuz_reveal solution)
        innerpuz = did_wallet.did_info.current_inner
        full_puzzle: Program = did_wallet_puzzles.create_fullpuz(
            innerpuz,
            did_wallet.did_info.my_did,
        )
        fullsol = Program.to(
            [
                [
                    parent_info.parent_name,
                    parent_info.inner_puzzle_hash,
                    parent_info.amount,
                ],
                coin.amount,
                innersol,
            ]
        )

        list_of_solutions = [
            CoinSolution(
                coin,
                clvm.to_sexp_f([full_puzzle, fullsol]),
            )
        ]
        # sign for AGG_SIG_ME
        message = bytes(coin.puzzle_hash) + bytes(coin.name())
        pubkey = did_wallet_puzzles.get_pubkey_from_innerpuz(innerpuz)
        index = await did_wallet.wallet_state_manager.puzzle_store.index_for_pubkey(
            pubkey
        )
        private = master_sk_to_wallet_sk(
            did_wallet.wallet_state_manager.private_key, index
        )
        signature = AugSchemeMPL.sign(private, message)
        sigs = [signature]
        aggsig = AugSchemeMPL.aggregate(sigs)
        spend_bundle = SpendBundle(list_of_solutions, aggsig)

        did_record = TransactionRecord(
            confirmed_at_index=uint32(0),
            created_at_time=uint64(int(time.time())),
            to_puzzle_hash=ph,
            amount=uint64(coin.amount),
            fee_amount=uint64(0),
            incoming=False,
            confirmed=False,
            sent=uint32(0),
            spend_bundle=spend_bundle,
            additions=spend_bundle.additions(),
            removals=spend_bundle.removals(),
            wallet_id=did_wallet.wallet_info.id,
            sent_to=[],
            trade_id=None,
        )

        await did_wallet.standard_wallet.push_transaction(did_record)

        await self.time_out_assert(15, wallet.get_confirmed_balance, 399999999999900)
        await self.time_out_assert(15, wallet.get_unconfirmed_balance, 399999999999900)
        ph2 = Program(binutils.assemble("(q ())")).get_tree_hash()
        for i in range(1, num_blocks):
            await full_node_1.farm_new_block(FarmNewBlockProtocol(ph2))
        # It ends in 900 so it's not gone through
        # Assert coin ID is failing
        await self.time_out_assert(15, wallet.get_confirmed_balance, 431999999999900)
        await self.time_out_assert(15, wallet.get_unconfirmed_balance, 431999999999900)
