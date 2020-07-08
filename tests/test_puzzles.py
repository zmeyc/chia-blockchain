import asyncio
import pytest
from src.protocols.wallet_protocol import SendTransaction
from src.simulator.simulator_protocol import FarmNewBlockProtocol
from src.types.coin import Coin
from src.wallet.escrow_wallet.recoverable_wallet import ProgramHash
from tests.setup_nodes import setup_simulators_and_wallets
from src.wallet.puzzles import (
    p2_conditions,
    p2_delegated_conditions,
    p2_delegated_puzzle,
    p2_puzzle_hash,
    p2_m_of_n_delegate_direct,
    p2_delegated_puzzle_or_hidden_puzzle,
)
from tests.keys import (
    bls_private_key_for_index,
    build_spend_bundle,
    conditions_for_payment,
    public_key_bytes_for_index,
    puzzle_hash_for_index,
    DEFAULT_KEYTOOL,
)


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()


async def farm_spendable_coin(full_node, puzzle_hash=puzzle_hash_for_index(0)):
    await full_node.farm_new_block(FarmNewBlockProtocol(puzzle_hash))
    for i in range(1, 5):
        await full_node.farm_new_block(FarmNewBlockProtocol(puzzle_hash_for_index(0)))
    coin_records = await full_node.coin_store.get_coin_records_by_puzzle_hash(puzzle_hash)
    assert len(coin_records) > 0
    return coin_records[0].coin


async def setup_full_node():
    async for _ in setup_simulators_and_wallets(
        1, 0, {"COINBASE_FREEZE_PERIOD": 0}
    ):
        return _


async def get_all_unspents(full_node):
    coin_records = await full_node.coin_store.get_unspent_coin_records()
    return [coin_record.coin.name() for coin_record in coin_records]


async def run_test(puzzle_hash, solution, payments):
    full_nodes, wallets = await setup_full_node()
    full_node, server = full_nodes[0]

    coin = await farm_spendable_coin(full_node, puzzle_hash)
    spend_bundle = build_spend_bundle(coin, solution)

    tx = SendTransaction(spend_bundle)
    msgs = [_ async for _ in full_node.send_transaction(tx)]

    # confirm it
    await farm_spendable_coin(full_node)

    # get unspents
    unspents = await get_all_unspents(full_node)

    # ensure all outputs are there
    for puzzle_hash, amount in payments:
        expected_coin = Coin(coin.name(), puzzle_hash, amount)
        name = expected_coin.name()
        assert name in unspents
        unspent = await full_node.coin_store.get_coin_record(name)
        # assert unspent.confirmed_block_index == 2
        # assert unspent.spent_block_index == 0


def default_payments_and_conditions(initial_index=1):
    payments = [
        (puzzle_hash_for_index(initial_index + 1), initial_index * 1000),
        (puzzle_hash_for_index(initial_index + 2), (initial_index + 1) * 1000),
    ]

    conditions = conditions_for_payment(payments)
    return payments, conditions


class TestPuzzles():
    @pytest.mark.asyncio
    async def test_p2_conditions(self):
        payments, conditions = default_payments_and_conditions()

        puzzle_hash = ProgramHash(p2_conditions.puzzle_for_conditions(conditions))
        solution = p2_conditions.solution_for_conditions(conditions)

        await run_test(puzzle_hash, solution, payments)

    @pytest.mark.asyncio
    async def test_p2_delegated_conditions(self):
        payments, conditions = default_payments_and_conditions()

        pk = public_key_bytes_for_index(1)

        puzzle_program = p2_delegated_conditions.puzzle_for_pk(pk)
        puzzle_hash = ProgramHash(puzzle_program)
        solution = p2_delegated_conditions.solution_for_conditions(
            puzzle_program, conditions
        )

        await run_test(puzzle_hash, solution, payments)

    @pytest.mark.asyncio
    async def test_p2_delegated_puzzle_simple(self):
        payments, conditions = default_payments_and_conditions()

        pk = public_key_bytes_for_index(1)

        puzzle_program = p2_delegated_puzzle.puzzle_for_pk(pk)
        puzzle_hash = ProgramHash(puzzle_program)
        solution = p2_delegated_puzzle.solution_for_conditions(
            puzzle_program, conditions
        )

        await run_test(puzzle_hash, solution, payments)

    @pytest.mark.asyncio
    async def test_p2_delegated_puzzle_graftroot(self):
        payments, conditions = default_payments_and_conditions()

        delegated_puzzle = p2_delegated_conditions.puzzle_for_pk(
            public_key_bytes_for_index(8)
        )
        delegated_solution = p2_delegated_conditions.solution_for_conditions(
            delegated_puzzle, conditions
        )

        puzzle_program = p2_delegated_puzzle.puzzle_for_pk(
            public_key_bytes_for_index(1)
        )
        puzzle_hash = ProgramHash(puzzle_program)
        solution = p2_delegated_puzzle.solution_for_delegated_puzzle(
            puzzle_program, delegated_solution
        )

        await run_test(puzzle_hash, solution, payments)

    @pytest.mark.asyncio
    async def test_p2_puzzle_hash(self):
        payments, conditions = default_payments_and_conditions()

        underlying_puzzle = p2_delegated_conditions.puzzle_for_pk(
            public_key_bytes_for_index(4)
        )
        underlying_solution = p2_delegated_conditions.solution_for_conditions(
            underlying_puzzle, conditions
        )
        underlying_puzzle_hash = ProgramHash(underlying_puzzle)

        puzzle_program = p2_puzzle_hash.puzzle_for_puzzle_hash(underlying_puzzle_hash)
        puzzle_hash = ProgramHash(puzzle_program)
        solution = p2_puzzle_hash.solution_for_puzzle_and_solution(
            underlying_puzzle, underlying_solution
        )

        await run_test(puzzle_hash, solution, payments)

    @pytest.mark.asyncio
    async def test_p2_m_of_n_delegated_puzzle(self):
        payments, conditions = default_payments_and_conditions()

        pks = [public_key_bytes_for_index(_) for _ in range(1, 6)]
        M = 3

        delegated_puzzle = p2_conditions.puzzle_for_conditions(conditions)
        delegated_solution = []

        puzzle_program = p2_m_of_n_delegate_direct.puzzle_for_m_of_public_key_list(
            M, pks
        )
        selectors = [1, [], [], 1, 1]
        solution = p2_m_of_n_delegate_direct.solution_for_delegated_puzzle(
            M, pks, selectors, delegated_puzzle, delegated_solution
        )
        puzzle_hash = ProgramHash(puzzle_program)

        await run_test(puzzle_hash, solution, payments)

    @pytest.mark.asyncio
    async def test_p2_delegated_puzzle_or_hidden_puzzle_with_hidden_puzzle(self):
        payments, conditions = default_payments_and_conditions()

        hidden_puzzle = p2_conditions.puzzle_for_conditions(conditions)
        hidden_public_key = public_key_bytes_for_index(10)

        puzzle = p2_delegated_puzzle_or_hidden_puzzle.puzzle_for_public_key_and_hidden_puzzle(
            hidden_public_key, hidden_puzzle
        )
        puzzle_hash = ProgramHash(puzzle)

        solution = p2_delegated_puzzle_or_hidden_puzzle.solution_with_hidden_puzzle(
            hidden_public_key, hidden_puzzle, []
        )

        await run_test(puzzle_hash, solution, payments)

    @pytest.mark.asyncio
    async def run_test_p2_delegated_puzzle_or_hidden_puzzle_with_delegated_puzzle(self, hidden_pub_key_index):
        payments, conditions = default_payments_and_conditions()

        hidden_puzzle = p2_conditions.puzzle_for_conditions(conditions)
        hidden_public_key = public_key_bytes_for_index(hidden_pub_key_index)

        puzzle = p2_delegated_puzzle_or_hidden_puzzle.puzzle_for_public_key_and_hidden_puzzle(
            hidden_public_key, hidden_puzzle
        )
        puzzle_hash = ProgramHash(puzzle)

        payable_payments, payable_conditions = default_payments_and_conditions(5)

        delegated_puzzle = p2_conditions.puzzle_for_conditions(payable_conditions)
        delegated_solution = []

        synthetic_public_key = p2_delegated_puzzle_or_hidden_puzzle.calculate_synthetic_public_key(
            hidden_public_key, hidden_puzzle
        )

        solution = p2_delegated_puzzle_or_hidden_puzzle.solution_with_delegated_puzzle(
            synthetic_public_key, delegated_puzzle, delegated_solution
        )

        hidden_puzzle_hash = ProgramHash(hidden_puzzle)
        synthetic_offset = p2_delegated_puzzle_or_hidden_puzzle.calculate_synthetic_offset(
            hidden_public_key, hidden_puzzle_hash
        )
        private_key = bls_private_key_for_index(hidden_pub_key_index)
        assert private_key.public_key() == hidden_public_key
        secret_exponent = private_key.secret_exponent()
        synthetic_secret_exponent = secret_exponent + synthetic_offset
        DEFAULT_KEYTOOL.add_secret_exponents([synthetic_secret_exponent])

        await run_test(puzzle_hash, solution, payable_payments)

    @pytest.mark.asyncio
    async def test_p2_delegated_puzzle_or_hidden_puzzle_with_delegated_puzzle(self):
        for hidden_pub_key_index in range(1, 10 ):
            await self.run_test_p2_delegated_puzzle_or_hidden_puzzle_with_delegated_puzzle(hidden_pub_key_index)
