from typing import Optional, Tuple, List, Dict

from blspy import G1Element

from src.types.condition_var_list import ConditionVarList
from src.types.condition_opcodes import ConditionOpcode
from src.types.coin import Coin
from src.types.program import Program
from src.types.sized_bytes import bytes32
from src.util.clvm import int_from_bytes
from src.util.ints import uint64
from src.util.errors import Err, ConsensusError


def parse_sexp_to_condition(
    sexp: Program,
) -> Tuple[Optional[Err], Optional[ConditionVarList]]:
    """
    Takes a ChiaLisp sexp and returns a ConditionVarList.
    If it fails, returns an Error
    """
    if not sexp.listp():
        return Err.SEXP_ERROR, None
    items = sexp.as_python()
    if not isinstance(items[0], bytes):
        return Err.INVALID_CONDITION, None
    try:
        opcode = ConditionOpcode(items[0])
    except ValueError:
        opcode = ConditionOpcode.UNKNOWN
    if len(items) == 3:
        return None, ConditionVarList(opcode, items[1], items[2])
    return None, ConditionVarList(opcode, items[1], None)


def parse_sexp_to_conditions(
    sexp: Program,
) -> Tuple[Optional[Err], Optional[List[ConditionVarList]]]:
    """
    Takes a ChiaLisp sexp (list) and returns the list of ConditionVarLists
    If it fails, returns as Error
    """
    results: List[ConditionVarList] = []
    try:
        for _ in sexp.as_iter():
            error, cvl = parse_sexp_to_condition(_)
            if error:
                return error, None
            results.append(cvl)  # type: ignore # noqa
    except ConsensusError:
        return Err.INVALID_CONDITION, None
    return None, results


def conditions_by_opcode(
    conditions: List[ConditionVarList],
) -> Dict[ConditionOpcode, List[ConditionVarList]]:
    """
    Takes a list of ConditionVarLists(cvl) and return dictionary of cvls keyed of their opcode
    """
    d: Dict[ConditionOpcode, List[ConditionVarList]] = {}
    cvl: ConditionVarList
    for cvl in conditions:
        if cvl.opcode not in d:
            d[cvl.opcode] = list()
        d[cvl.opcode].append(cvl)
    return d


def pkm_pairs_for_conditions_dict(
    conditions_dict: Dict[ConditionOpcode, List[ConditionVarList]],
    coin_name: bytes32 = None,
) -> List[Tuple[G1Element, bytes]]:
    ret: List[Tuple[G1Element, bytes]] = []
    for cvl in conditions_dict.get(ConditionOpcode.AGG_SIG, []):
        # TODO: check types
        # assert len(_) == 3
        assert cvl.vars[1] is not None
        ret.append((G1Element.from_bytes(cvl.vars[0]), cvl.vars[1]))
    if coin_name is not None:
        for cvl in conditions_dict.get(ConditionOpcode.AGG_SIG_ME, []):
            ret.append((G1Element.from_bytes(cvl.vars[0]), cvl.vars[1] + coin_name))
    return ret


def aggsig_in_conditions_dict(
    conditions_dict: Dict[ConditionOpcode, List[ConditionVarList]]
) -> List[ConditionVarList]:
    agg_sig_conditions = []
    for _ in conditions_dict.get(ConditionOpcode.AGG_SIG, []):
        agg_sig_conditions.append(_)
    return agg_sig_conditions


def created_outputs_for_conditions_dict(
    conditions_dict: Dict[ConditionOpcode, List[ConditionVarList]],
    input_coin_name: bytes32,
) -> List[Coin]:
    output_coins = []
    for cvl in conditions_dict.get(ConditionOpcode.CREATE_COIN, []):
        # TODO: check condition very carefully
        # (ensure there are the correct number and type of parameters)
        # maybe write a type-checking framework for conditions
        # and don't just fail with asserts
        puzzle_hash, amount_bin = cvl.vars[0], cvl.vars[1]
        amount = int_from_bytes(amount_bin)
        coin = Coin(input_coin_name, puzzle_hash, amount)
        output_coins.append(coin)
    return output_coins


def conditions_dict_for_solution(
    solution,
) -> Tuple[
    Optional[Err], Optional[Dict[ConditionOpcode, List[ConditionVarList]]], uint64
]:
    error, result, cost = conditions_for_solution(solution)
    if error or result is None:
        return error, None, uint64(0)
    return None, conditions_by_opcode(result), cost


def conditions_for_solution(
    solution_program,
) -> Tuple[Optional[Err], Optional[List[ConditionVarList]], uint64]:
    # get the standard script for a puzzle hash and feed in the solution
    args = Program.to(solution_program)
    try:
        puzzle_sexp = args.first()
        solution_sexp = args.rest().first()
        cost, r = puzzle_sexp.run_with_cost(solution_sexp)
        error, result = parse_sexp_to_conditions(r)
        return error, result, cost
    except Program.EvalError:
        return Err.SEXP_ERROR, None, uint64(0)
