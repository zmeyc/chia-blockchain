from typing import List
from blspy import AugSchemeMPL

from src.types.coin import Coin
from src.types.program import Program
from src.util.condition_tools import (
    created_outputs_for_conditions_dict,
    conditions_dict_for_solution,
    pkm_pairs_for_conditions_dict
)


def additions_for_solution(coin_name, solution) -> List[Coin]:
    """
    Checks the conditions created by CoinSolution and returns the list of all coins created
    """
    err, dic, cost = conditions_dict_for_solution(solution)
    if err or dic is None:
        return []
    return created_outputs_for_conditions_dict(dic, coin_name)


def check_aggsig(spend_bundle):
    pks = []
    msgs = []
    for coin_solution in spend_bundle.coin_solutions:
        coin, solution_pair = coin_solution.coin, Program.to(coin_solution.solution)
        puzzle_reveal = solution_pair.first()
        solution = solution_pair.rest().first()
        error, conditions, cost = conditions_dict_for_solution(
            Program.to([puzzle_reveal, solution])
        )
        if error:
            return False
        elif conditions is not None:
            for pk, m in pkm_pairs_for_conditions_dict(conditions, coin.name()):
                pks.append(pk)
                msgs.append(m)
    if len(msgs) > 0:
        validates = AugSchemeMPL.aggregate_verify(
            pks, msgs, spend_bundle.aggregated_signature
        )
    else:
        validates = True
    return validates
