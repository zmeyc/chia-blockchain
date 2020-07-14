import logging
import hashlib
import time
from collections import defaultdict
from decimal import Decimal
from enum import IntEnum
from typing import Any, Optional, List

import cbor2
import clvm
from .keychain import Keychain
from src.wallet.puzzles import p2_delegated_puzzle_or_hidden_puzzle as taproot
from .chialisp import *

from src.types.condition_opcodes import ConditionOpcode
from .hexbytes import hexbytes
from src.types.program import Program
from src.types.coin_solution import CoinSolution
from src.types.spend_bundle import SpendBundle
from src.types.BLSSignature import BLSSignature
from src.wallet.wallet import Wallet

from clvm_tools import binutils
from clvm import to_sexp_f
from src.util.condition_tools import conditions_by_opcode, \
    conditions_for_solution, \
    hash_key_pairs_for_conditions_dict, \
    conditions_dict_for_solution

from src.wallet.puzzles.puzzle_utils import make_create_coin_condition

from fractions import Fraction
import math

from blspy import ExtendedPublicKey

from ..BLSPrivateKey import BLSPrivateKey
from ..transaction_record import TransactionRecord
from ..util.wallet_types import WalletType
from ..wallet_info import WalletInfo
from ..wallet_state_manager import WalletStateManager
from ...types.coin import Coin
from ...types.condition_var_pair import ConditionVarPair
from ...types.sized_bytes import bytes32
from ...util.ints import uint64, uint32


def ProgramHash(program):
    return program.get_tree_hash()


def hash_sha256(val):
    return hashlib.sha256(val).digest()


def make_solution(parent,
                  puzzlehash,
                  value,
                  stake_factor,
                  primaries=[],
                  recovery=False,
                  hidden_public_key=None,
                  hidden_puzzle=None):
    conditions = []
    for primary in primaries:
        conditions.append(make_create_coin_condition(primary['puzzlehash'], primary['amount']))
    conditions = [binutils.assemble("#q"), conditions]
    solution = [conditions, [], parent, puzzlehash, value, math.floor(value * stake_factor)]
    delegated_puzzle = Program(to_sexp_f(conditions))
    if recovery:
        solution = taproot.solution_with_hidden_puzzle(hidden_public_key, hidden_puzzle, solution)
    else:
        synthetic_public_key = taproot.calculate_synthetic_public_key(hidden_public_key,
                                                                      hidden_puzzle)
        solution = taproot.solution_with_delegated_puzzle(synthetic_public_key,
                                                          delegated_puzzle,
                                                          solution)
    program = Program(to_sexp_f(solution))
    return program


def get_destination_puzzle_hash(solution):
    error, conditions_dict, cost = conditions_dict_for_solution(solution)
    val = conditions_dict.get(ConditionOpcode.CREATE_COIN, [])
    assert (len(val) == 1)
    assert (type(val[0] is ConditionVarPair))
    return val[0].var1


def aggsig_condition(key):
    op_aggsig = ConditionOpcode.AGG_SIG[0]
    return make_list(quote(op_aggsig),
                     quote(f'0x{hexbytes(key)}'),
                     sha256tree(args(0)))


def recovery_string_to_dict(recovery_string):
    recovery_dict = cbor2.loads(bytes.fromhex(recovery_string))
    recovery_dict['root_public_key'] = ExtendedPublicKey.from_bytes(recovery_dict['root_public_key'])
    recovery_dict['secret_key'] = BLSPrivateKey.from_bytes(recovery_dict['secret_key'])
    recovery_dict['stake_factor'] = Decimal(recovery_dict['stake_factor'])
    return recovery_dict


class InsufficientFundsError(BaseException):
    pass


class DurationType(IntEnum):
    BLOCKS = 1
    WALLCLOCK_TIME = 2


class RecoverableWallet(Wallet):
    wallet_info: WalletInfo

    def __init__(self,
                 wallet_state_manager: WalletStateManager,
                 stake_factor: Decimal,
                 escrow_duration: int,
                 duration_type: DurationType):
        super().__init__()
        self.wallet_state_manager = wallet_state_manager
        self.escrow_duration = escrow_duration
        self.duration_type = duration_type
        self.stake_factor = stake_factor
        self.backup_hd_root_public_key = self.wallet_state_manager.private_key.get_extended_public_key()
        self.backup_private_key = self.wallet_state_manager.private_key.private_child(0).get_private_key()
        self.next_address = 1
        self.escrow_coins = defaultdict(set)
        self.keychain = Keychain()

    def get_recovery_public_key(self):
        return self.backup_private_key.get_public_key()

    def get_recovery_private_key(self):
        return self.backup_private_key

    def get_recovery_hd_root_public_key(self):
        return self.backup_hd_root_public_key

    def get_escrow_duration(self):
        return self.escrow_duration

    def get_duration_type(self):
        return self.duration_type

    def get_stake_factor(self):
        return self.stake_factor

    def get_backup_string(self):
        d = dict()
        d['root_public_key'] = bytes(self.get_recovery_hd_root_public_key())
        d['secret_key'] = bytes(self.get_recovery_private_key())
        d['escrow_duration'] = self.get_escrow_duration()
        d['duration_type'] = self.get_duration_type()
        d['stake_factor'] = self.get_stake_factor().as_tuple()
        return str(hexbytes(cbor2.dumps(d)))

    def get_escrow_puzzle_with_params(self, recovery_pubkey, pubkey, duration, duration_type):
        op_block_age_exceeds = ConditionOpcode.ASSERT_BLOCK_AGE_EXCEEDS[0]
        op_time_exceeds = ConditionOpcode.ASSERT_TIME_EXCEEDS[0]
        solution = args(0)
        solution_args = args(1)
        secure_switch = args(2)
        evaluate_solution = eval(solution, solution_args)
        standard_conditions = make_list(aggsig_condition(pubkey),
                                        terminator=evaluate_solution)
        if duration_type == DurationType.BLOCKS:
            op_code = op_block_age_exceeds
        elif duration_type == DurationType.WALLCLOCK_TIME:
            op_code = op_time_exceeds
        recovery_conditions = make_list(aggsig_condition(recovery_pubkey),
                                        make_list(quote(op_code),
                                                  quote(duration)),
                                        terminator=evaluate_solution)
        escrow_puzzle = make_if(is_zero(secure_switch),
                                standard_conditions,
                                recovery_conditions)
        program = Program(binutils.assemble(escrow_puzzle))
        return program

    def get_new_puzzle_with_params_and_root(self, recovery_pubkey, pubkey, stake_factor, duration, duration_type):
        escrow_conditions_program = self.get_send_to_escrow_puzzle(recovery_pubkey,
                                                                   pubkey,
                                                                   stake_factor,
                                                                   duration,
                                                                   duration_type)

        return taproot.puzzle_for_public_key_and_hidden_puzzle(recovery_pubkey,
                                                               escrow_conditions_program)

    def get_send_to_escrow_puzzle(self, recovery_pubkey, pubkey, stake_factor, duration, duration_type):
        op_create = ConditionOpcode.CREATE_COIN[0]
        op_consumed = ConditionOpcode.ASSERT_COIN_CONSUMED[0]
        solution = args(0)
        solution_args = args(1)
        parent = args(2)
        puzzle_hash = args(3)
        value = args(4)
        new_value = args(5)

        escrow_program = self.get_escrow_puzzle_with_params(recovery_pubkey, pubkey, duration, duration_type)
        escrow_puzzlehash = f'0x' + str(hexbytes(ProgramHash(escrow_program)))
        f = Fraction(stake_factor)
        stake_factor_numerator = quote(f.numerator)
        stake_factor_denominator = quote(f.denominator)
        create_condition = make_if(equal(multiply(new_value, stake_factor_denominator),
                                         multiply(value, stake_factor_numerator)),
                                   make_list(quote(op_create), quote(escrow_puzzlehash), new_value),
                                   fail())
        coin_id = sha256(parent, puzzle_hash, value)
        consumed_condition = make_list(quote(op_consumed), coin_id)
        escrow_conditions = make_list(create_condition, consumed_condition)
        program = Program(binutils.assemble(escrow_conditions))
        return program

    def get_new_puzzle_with_params(self, pubkey, stake_factor, escrow_duration, duration_type):
        return self.get_new_puzzle_with_params_and_root(bytes(self.get_recovery_public_key()),
                                                        pubkey,
                                                        stake_factor,
                                                        escrow_duration,
                                                        duration_type)

    async def get_new_puzzlehash(self) -> bytes32:
        return (
            await self.wallet_state_manager.get_unused_derivation_record(
                self.wallet_info.id
            )
        ).puzzle_hash

    def can_generate_puzzle_hash(self, hash):
        return any(map(lambda child: hash == ProgramHash(self.get_new_puzzle_with_params(
            bytes(self.wallet_state_manager.private_key.public_child(child)),
            self.get_stake_factor(),
            self.get_escrow_duration(),
            self.get_duration_type())),
            reversed(range(self.next_address))))

    def is_in_escrow(self, coin):
        keys = self.get_keys_for_escrow_puzzle(coin.puzzle_hash)
        return keys is not None

    def balance(self):
        return sum([coin.amount for coin in self.my_utxos])

    def notify(self, additions, deletions):
        for coin in deletions:
            if coin in self.my_utxos:
                self.my_utxos.remove(coin)
                self.current_balance -= coin.amount
            for _, coin_set in self.escrow_coins.items():
                if coin in coin_set:
                    print(f'Notice: {coin.name()} was removed from escrow by clawback')
                    coin_set.remove(coin)
        for coin in additions:
            if self.can_generate_puzzle_hash(coin.puzzle_hash):
                self.current_balance += coin.amount
                self.my_utxos.add(coin)

        self.temp_utxos = self.my_utxos.copy()
        self.temp_balance = self.current_balance

    def can_generate_puzzle_hash_with_root_public_key(self,
                                                      hash,
                                                      root_public_key_serialized,
                                                      stake_factor,
                                                      escrow_duration,
                                                      duration_type):
        root_public_key = ExtendedPublicKey.from_bytes(root_public_key_serialized)
        recovery_pubkey = bytes(root_public_key.public_child(0).get_public_key())
        return any(map(lambda child: hash == ProgramHash(self.get_new_puzzle_with_params_and_root(
            recovery_pubkey,
            bytes(root_public_key.public_child(child).get_public_key()),
            stake_factor,
            escrow_duration,
            duration_type)),
                reversed(range(20))))  # incorrect

    def find_pubkey_for_hash(self, hash, root_public_key_serialized, stake_factor, escrow_duration, duration_type):
        root_public_key = ExtendedPublicKey.from_bytes(root_public_key_serialized)
        recovery_pubkey = bytes(root_public_key.public_child(0).get_public_key())
        for child in reversed(range(20)):  # incorrect
            pubkey = bytes(root_public_key.public_child(child).get_public_key())
            puzzle = self.get_new_puzzle_with_params_and_root(recovery_pubkey,
                                                              pubkey,
                                                              stake_factor,
                                                              escrow_duration,
                                                              duration_type)
            puzzlehash = ProgramHash(puzzle)
            if hash == puzzlehash:
                return pubkey

    def get_keys(self, hash):
        for child in range(self.next_address):
            pubkey = self.wallet_state_manager.private_key.public_child(child).get_public_key()
            if hash == ProgramHash(self.get_new_puzzle_with_params(bytes(pubkey),
                                                                   self.get_stake_factor(),
                                                                   self.get_escrow_duration(),
                                                                   self.get_duration_type())):
                return pubkey, self.wallet_state_manager.private_key.private_child(child).get_private_key()

    async def generate_unsigned_transaction(self, amount, newpuzzlehash):
        stake_factor = self.get_stake_factor()
        utxos = await self.select_coins(amount)
        if utxos is None:
            raise InsufficientFundsError
        coin_solutions = []
        output_id = None
        spend_value = sum([coin.amount for coin in utxos])
        change = spend_value - amount
        for coin in utxos:
            puzzle_hash = coin.puzzle_hash

            pubkey, secret_key = await self.wallet_state_manager.get_keys(puzzle_hash)
            hidden_public_key = bytes(self.get_recovery_public_key())
            hidden_puzzle = self.get_send_to_escrow_puzzle(hidden_public_key,
                                                           pubkey,
                                                           stake_factor,
                                                           self.get_escrow_duration(),
                                                           self.get_duration_type())
            hidden_puzzle_hash = ProgramHash(hidden_puzzle)
            synthetic_offset = taproot.calculate_synthetic_offset(hidden_public_key, hidden_puzzle_hash)
            secret_exponent = BLSPrivateKey(
                self.wallet_state_manager.private_key.private_child(0).get_private_key()).secret_exponent()
            synthetic_secret_exponent = secret_exponent + synthetic_offset
            self.keychain.add_secret_exponents([synthetic_secret_exponent])

            if output_id is None:
                primaries = [{'puzzlehash': newpuzzlehash, 'amount': amount}]
                if change > 0:
                    changepuzzlehash = await self.get_new_puzzlehash()
                    primaries.append({'puzzlehash': changepuzzlehash, 'amount': change})
                solution = make_solution(coin.parent_coin_info, coin.puzzle_hash, coin.amount, stake_factor,
                                         hidden_public_key=hidden_public_key,
                                         hidden_puzzle=hidden_puzzle,
                                         primaries=primaries)
                output_id = hash_sha256(coin.name() + newpuzzlehash)
            else:
                solution = make_solution(coin.parent_coin_info, coin.puzzle_hash, coin.amount, stake_factor,
                                         hidden_public_key=hidden_public_key,
                                         hidden_puzzle=hidden_puzzle)
            coin_solutions.append(CoinSolution(coin, solution))
        return coin_solutions

    async def generate_unsigned_transaction_without_recipient(self, amount):
        stake_factor = self.get_stake_factor()
        utxos = await self.select_coins(amount)
        if utxos is None:
            raise InsufficientFundsError
        coin_solutions = []
        output_id = None
        spend_value = sum([coin.amount for coin in utxos])
        change = spend_value - amount
        for coin in utxos:
            puzzle_hash = coin.puzzle_hash

            pubkey, secretkey = self.get_keys(puzzle_hash)
            hidden_public_key = bytes(self.get_recovery_public_key())
            hidden_puzzle = self.get_send_to_escrow_puzzle(hidden_public_key,
                                                           pubkey,
                                                           stake_factor,
                                                           self.get_escrow_duration(),
                                                           self.get_duration_type())
            hidden_puzzle_hash = ProgramHash(hidden_puzzle)
            synthetic_offset = taproot.calculate_synthetic_offset(hidden_public_key, hidden_puzzle_hash)
            secret_exponent = BLSPrivateKey(
                self.wallet_state_manager.private_key.private_child(0).get_private_key()).secret_exponent()
            synthetic_secret_exponent = secret_exponent + synthetic_offset
            self.keychain.add_secret_exponents([synthetic_secret_exponent])

            if output_id is None:
                primaries = []
                if change > 0:
                    changepuzzlehash = await self.get_new_puzzlehash()
                    primaries.append({'puzzlehash': changepuzzlehash, 'amount': change})
                solution = make_solution(coin.parent_coin_info, coin.puzzle_hash, coin.amount, stake_factor,
                                         hidden_public_key=hidden_public_key,
                                         hidden_puzzle=hidden_puzzle,
                                         primaries=primaries)
                output_id = True
            else:
                solution = make_solution(coin.parent_coin_info, coin.puzzle_hash, coin.amount, stake_factor)
            coin_solutions.append(CoinSolution(coin, solution))
        return coin_solutions

    async def generate_recovery_to_escrow_transaction(self,
                                                      coin,
                                                      recovery_pubkey,
                                                      pubkey,
                                                      stake_factor,
                                                      escrow_duration,
                                                      duration_type):
        hidden_puzzle = self.get_send_to_escrow_puzzle(recovery_pubkey,
                                                       pubkey,
                                                       stake_factor,
                                                       escrow_duration,
                                                       duration_type)

        solution = make_solution(coin.parent_coin_info,
                                 coin.puzzle_hash,
                                 coin.amount,
                                 stake_factor,
                                 recovery=True,
                                 hidden_public_key=recovery_pubkey,
                                 hidden_puzzle=hidden_puzzle)

        secret_exponent = BLSPrivateKey(self.get_recovery_private_key()).secret_exponent()
        self.keychain.add_secret_exponents([secret_exponent])
        destination_puzzle_hash = get_destination_puzzle_hash(solution)
        staked_amount = math.ceil(coin.amount * (stake_factor - 1))
        coin_solutions = await self.generate_unsigned_transaction_without_recipient(staked_amount)
        coin_solutions.append(CoinSolution(coin, solution))
        return coin_solutions, destination_puzzle_hash, coin.amount + staked_amount

    async def generate_signed_recovery_to_escrow_transaction(self,
                                                             coin,
                                                             recovery_pubkey,
                                                             pubkey,
                                                             stake_factor,
                                                             escrow_duration,
                                                             duration_type):
        transaction, destination_puzzlehash, amount = await self.generate_recovery_to_escrow_transaction(coin,
                                                                                                         recovery_pubkey,
                                                                                                         pubkey,
                                                                                                         stake_factor,
                                                                                                         escrow_duration,
                                                                                                         duration_type)
        spend_bundle = self.sign_transaction(transaction)
        return spend_bundle, destination_puzzlehash, amount

    def sign_transaction(self, coin_solutions: [CoinSolution]):
        signatures = []
        for coin_solution in coin_solutions:
            signature = self.keychain.signature_for_solution(coin_solution.solution)
            signatures.append(signature)
        aggsig = BLSSignature.aggregate(signatures)
        spend_bundle = SpendBundle(coin_solutions, aggsig)
        return spend_bundle

    def get_keys_for_escrow_puzzle(self, hash):
        for child in range(self.next_address):
            pubkey = self.wallet_state_manager.private_key.public_child(child).get_public_key()
            escrow_hash = ProgramHash(self.get_escrow_puzzle_with_params(bytes(self.get_recovery_public_key()),
                                                                         bytes(pubkey),
                                                                         self.get_escrow_duration(),
                                                                         self.get_duration_type()))
            if hash == escrow_hash:
                return pubkey,\
                       BLSPrivateKey(self.wallet_state_manager.private_key.private_child(child).get_private_key())

    async def generate_signed_transaction(
            self,
            amount: uint64,
            puzzle_hash: bytes32
    ) -> Optional[TransactionRecord]:
        """ Use this to generate transaction. """

        transaction = await self.generate_unsigned_transaction(
            amount, puzzle_hash)
        if len(transaction) == 0:
            self.log.info("Unsigned transaction not generated")
            return None

        self.log.info("About to sign a transaction")
        spend_bundle: Optional[SpendBundle] = self.sign_transaction(transaction)
        if spend_bundle is None:
            return None

        now = uint64(int(time.time()))
        add_list: List[Coin] = []
        rem_list: List[Coin] = []

        for add in spend_bundle.additions():
            add_list.append(add)
        for rem in spend_bundle.removals():
            rem_list.append(rem)

        tx_record = TransactionRecord(
            confirmed_at_index=uint32(0),
            created_at_time=now,
            to_puzzle_hash=puzzle_hash,
            amount=uint64(amount),
            fee_amount=uint64(0),
            incoming=False,
            confirmed=False,
            sent=uint32(0),
            spend_bundle=spend_bundle,
            additions=add_list,
            removals=rem_list,
            wallet_id=self.wallet_info.id,
            sent_to=[],
        )

        return tx_record

    async def generate_clawback_transaction(self, coins):
        signatures = []
        coin_solutions = []
        for coin in coins:
            pubkey, secret_key = self.get_keys_for_escrow_puzzle(coin.puzzle_hash)
            puzzle = self.get_escrow_puzzle_with_params(bytes(self.get_recovery_public_key()),
                                                        bytes(pubkey),
                                                        self.get_escrow_duration(),
                                                        self.get_duration_type())

            op_create_coin = ConditionOpcode.CREATE_COIN[0]
            puzzlehash = f'0x' + str(hexbytes(await self.get_new_puzzlehash()))
            solution_src = sexp(quote(sexp(sexp(op_create_coin, puzzlehash, coin.amount))), sexp(), 0)
            solution = Program(binutils.assemble(solution_src))

            puzzle_solution_list = clvm.to_sexp_f([puzzle, solution])
            coin_solution = CoinSolution(coin, puzzle_solution_list)
            coin_solutions.append(coin_solution)

            error, result, cost = conditions_for_solution(puzzle_solution_list)
            conditions_dict = conditions_by_opcode(result)
            for _ in hash_key_pairs_for_conditions_dict(conditions_dict):
                signature = secret_key.sign(_.message_hash)
                signatures.append(signature)

        aggsig = BLSSignature.aggregate(signatures)
        spend_bundle = SpendBundle(coin_solutions, aggsig)
        return spend_bundle

    def find_pubkey_for_escrow_puzzle(self, coin, root_public_key, duration, duration_type):
        recovery_pubkey = bytes(root_public_key.public_child(0).get_public_key())

        child = 0
        while True:
            pubkey = root_public_key.public_child(child).get_public_key()
            test_hash = ProgramHash(self.get_escrow_puzzle_with_params(recovery_pubkey,
                                                                       bytes(pubkey),
                                                                       duration,
                                                                       duration_type))
            if coin.puzzle_hash == test_hash:
                return pubkey
            child += 1

    async def generate_recovery_transaction(self, coins, root_public_key, secret_key, escrow_duration, duration_type):
        recovery_pubkey = bytes(root_public_key.public_child(0).get_public_key())
        signatures = []
        coin_solutions = []
        for coin in coins:
            pubkey = self.find_pubkey_for_escrow_puzzle(coin, root_public_key, escrow_duration, duration_type)
            puzzle = self.get_escrow_puzzle_with_params(recovery_pubkey, bytes(pubkey), escrow_duration, duration_type)

            op_create_coin = ConditionOpcode.CREATE_COIN[0]
            puzzlehash = f'0x' + str(hexbytes(await self.get_new_puzzlehash()))
            solution_src = sexp(quote(sexp(sexp(op_create_coin, puzzlehash, coin.amount))), sexp(), 1)
            solution = Program(binutils.assemble(solution_src))

            puzzle_solution_list = clvm.to_sexp_f([puzzle, solution])
            coin_solution = CoinSolution(coin, puzzle_solution_list)
            coin_solutions.append(coin_solution)

            error, result, cost = conditions_for_solution(puzzle_solution_list)
            conditions_dict = conditions_by_opcode(result)
            for _ in hash_key_pairs_for_conditions_dict(conditions_dict):
                signature = secret_key.sign(_.message_hash)
                signatures.append(signature)

        aggsig = BLSSignature.aggregate(signatures)
        spend_bundle = SpendBundle(coin_solutions, aggsig)
        return spend_bundle

    def puzzle_for_pk(self, pubkey) -> Program:
        program = self.get_new_puzzle_with_params(pubkey,
                                                  self.get_stake_factor(),
                                                  self.get_escrow_duration(),
                                                  self.get_duration_type())
        return program

    @staticmethod
    async def create(
            wallet_state_manager: Any,
            stake_factor: Decimal,
            escrow_duration: int,
            duration_type: DurationType,
            name: str = "Escrow Wallet",
    ):
        self = RecoverableWallet(wallet_state_manager, stake_factor, escrow_duration, duration_type)

        if name:
            self.log = logging.getLogger(name)
        else:
            self.log = logging.getLogger(__name__)

        self.wallet_info = await wallet_state_manager.user_store.create_wallet(
            name, WalletType.RECOVERABLE, None
        )
        if self.wallet_info is None:
            raise ValueError("Internal Error")
        await self.wallet_state_manager.add_new_wallet(self, self.wallet_info.id)
        return self

    async def get_unconfirmed_spendable(self) -> uint64:
        return await self.wallet_state_manager.get_unconfirmed_spendable_for_wallet(
            self.wallet_info.id
        )

    async def restore(self, recovery_string, full_node):
        recovery_dict = recovery_string_to_dict(recovery_string)
        root_public_key_serialized = bytes(recovery_dict['root_public_key'])
        recovery_pubkey = bytes(recovery_dict['root_public_key'].public_child(0).get_public_key())
        coin_records = await full_node.coin_store.get_unspent_coin_records()
        unspent_coins = [coin_record.coin for coin_record in coin_records]
        recoverable_coins = []
        print('scanning', end='')
        for coin in unspent_coins:
            if self.can_generate_puzzle_hash_with_root_public_key(coin.puzzle_hash,
                                                                  root_public_key_serialized,
                                                                  recovery_dict['stake_factor'],
                                                                  recovery_dict['escrow_duration'],
                                                                  recovery_dict['duration_type']):
                recoverable_coins.append(coin)
                print('*', end='', flush=True)
            else:
                print('.', end='', flush=True)
        recoverable_amount = sum([coin.amount for coin in recoverable_coins])
        print(f'\nFound {len(recoverable_coins)} coins totaling {recoverable_amount}')
        stake_amount = round(recoverable_amount * (recovery_dict['stake_factor'] - 1))
        if await self.get_unconfirmed_spendable() < stake_amount:
            print(f'Insufficient funds to stake the recovery process. {stake_amount} needed.')
            return
        for coin in recoverable_coins:
            print(f'Coin ID: {coin.name()}, Amount: {coin.amount}')
            pubkey = self.find_pubkey_for_hash(coin.puzzle_hash,
                                               root_public_key_serialized,
                                               recovery_dict['stake_factor'],
                                               recovery_dict['escrow_duration'],
                                               recovery_dict['duration_type'])
            if pubkey is None:
                print("Error: could not find pubkey for coin to recover")
                return
            spend_bundle, destination_puzzlehash, amount = \
                await self.generate_signed_recovery_to_escrow_transaction(coin,
                                                                          recovery_pubkey,
                                                                          pubkey,
                                                                          recovery_dict['stake_factor'],
                                                                          recovery_dict['escrow_duration'],
                                                                          recovery_dict['duration_type'])
            now = uint64(int(time.time()))
            add_list: List[Coin] = []
            rem_list: List[Coin] = []
            for addition in spend_bundle.additions():
                add_list.append(addition)
            for removal in spend_bundle.removals():
                rem_list.append(removal)
            tx_record = TransactionRecord(
                confirmed_at_index=uint32(0),
                created_at_time=now,
                to_puzzle_hash=destination_puzzlehash,
                amount=uint64(amount),
                fee_amount=uint64(0),
                incoming=False,
                confirmed=False,
                sent=uint32(0),
                spend_bundle=spend_bundle,
                additions=add_list,
                removals=rem_list,
                wallet_id=self.wallet_info.id,
                sent_to=[],
            )
            await self.push_transaction(tx_record)
            child = Coin(coin.name(), destination_puzzlehash, amount)
            self.escrow_coins[recovery_string].add(child)

    async def recover_escrow_coins(self):
        removals = set()
        for recovery_string, coin_set in self.escrow_coins.items():
            for coin in coin_set:
                self.log.info('Attempting to recover ' + str(coin.name()))
            recovery_dict = recovery_string_to_dict(recovery_string)
            root_public_key = recovery_dict['root_public_key']
            secret_key = recovery_dict['secret_key']
            escrow_duration = recovery_dict['escrow_duration']
            duration_type = recovery_dict['duration_type']

            spend_bundle = await self.generate_recovery_transaction(coin_set,
                                                                    root_public_key,
                                                                    secret_key,
                                                                    escrow_duration,
                                                                    duration_type)
            now = uint64(int(time.time()))
            add_list: List[Coin] = []
            rem_list: List[Coin] = []
            for addition in spend_bundle.additions():
                add_list.append(addition)
            for removal in spend_bundle.removals():
                rem_list.append(removal)
            tx_record = TransactionRecord(
                confirmed_at_index=uint32(0),
                created_at_time=now,
                to_puzzle_hash=await self.get_new_puzzlehash(),  # incorrect
                amount=uint64(0),                                # incorrect
                fee_amount=uint64(0),
                incoming=False,
                confirmed=False,
                sent=uint32(0),
                spend_bundle=spend_bundle,
                additions=add_list,
                removals=rem_list,
                wallet_id=self.wallet_info.id,
                sent_to=[],
            )
            await self.push_transaction(tx_record)
        # for recovery_string in removals:
        #     self.escrow_coins.pop(recovery_string)

    async def clawback(self, coins):
        spend_bundle = await self.generate_clawback_transaction(coins)
        now = uint64(int(time.time()))
        add_list: List[Coin] = []
        rem_list: List[Coin] = []
        for addition in spend_bundle.additions():
            add_list.append(addition)
        for removal in spend_bundle.removals():
            rem_list.append(removal)
        tx_record = TransactionRecord(
            confirmed_at_index=uint32(0),
            created_at_time=now,
            to_puzzle_hash=await self.get_new_puzzlehash(),  # incorrect
            amount=uint64(0),  # incorrect
            fee_amount=uint64(0),
            incoming=False,
            confirmed=False,
            sent=uint32(0),
            spend_bundle=spend_bundle,
            additions=add_list,
            removals=rem_list,
            wallet_id=self.wallet_info.id,
            sent_to=[],
        )
        await self.push_transaction(tx_record)