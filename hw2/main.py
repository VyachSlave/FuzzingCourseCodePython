import json
import random
import re
from typing import Union, Tuple, Dict, Any, List, Callable

import dirtyjson as dj
from fuzzingbook.GreyboxFuzzer import PowerSchedule, Seed, GreyboxFuzzer
from fuzzingbook.MutationFuzzer import FunctionCoverageRunner

from hw1.main import StringMutator

"""
    Домашняя работа (часть 1). Дедлайн 2 недели!!!
    ● Описать в нужном формате JSON грамматику (или ее часть)
    ● Сгенерировать initial_seed с помощью simple_grammar_fuzzer
    ● Выбрать случайную библиотеку для парсинга JSON
    ● Попробовать её пофаззить с помощью одного из ранее написанных
    мутационных coverage-guided фаззеров (мб реализовать мутации)
    ● Зафиксировать результаты по покрытию и результатам
"""

Expansion = Union[str, Tuple[str, Dict[str, Any]]]
Grammar = Dict[str, List[Expansion]]

CHARSET = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
        'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D',
        'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
        'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', '!', '#', '$', '%', '&', "'", '(', ')',
        '*', '+', ',', '-', '.', '/', ':', ';', '<', '=',
        '>', '?', '@', '[', ']', '^', '_', '`', '{', '|',
        '}', '~', ' ',
]

JSON_GRAMMAR = {
    '<start>': ['<json>'],
    '<json>': ["<element>"],
    '<element>': ['<ws><value><ws>'],
    '<object>': ['{<ws>}', '{<members>}'],
    '<value>': [
        '<object>', '<array>', '<string>', '<number>',
        'true', 'false', 'null',
    ],
    '<members>': ['<member><symbol-2>'],
    '<member>': ['<ws><string><ws>:<element>'],
    '<array>': ['[<ws>]', '[<elements>]'],
    '<elements>': ['<element><symbol-1-1>'],
    '<string>': ['"<characters>"'],
    '<characters>': ['<character-1>'],
    '<character>': CHARSET,
    '<number>': ['<int><frac><exp>'],
    '<int>': ['<digit>', '<onenine><digits>', '-<digit>', '-<onenine><digits>'],
    '<digits>': ['<digit-1>'],
    '<digit>': ['0', '<onenine>'],
    '<onenine>': ['1', '2', '3', '4', '5', '6', '7', '8', '9'],
    '<frac>': ['', '.<digits>'],
    '<exp>': ['', 'E<sign><digits>', 'e<sign><digits>'],
    '<sign>': ['', '+', '-'],
    '<ws>': [' '],
    '<symbol>': [',<members>'],
    '<symbol-1>': [',<elements>'],
    '<symbol-2>': ['', '<symbol><symbol-2>'],
    '<symbol-1-1>': ['', '<symbol-1><symbol-1-1>'],
    '<character-1>': ['', '<character><character-1>'],
    '<digit-1>': ['<digit>', '<digit><digit-1>']
}

def nonterminals(expansion: Expansion) -> list:
    if isinstance(expansion, tuple):
        expansion = expansion[0]

    return re.compile(r'(<[^<> ]*>)').findall(expansion)

def simple_grammar_fuzzer(
        grammar: Grammar, start_symbol: str = "<start>",
        max_nonterminals: int = 10, max_expansion_trials: int = 100,
        log: bool = False
) -> str:
    term = start_symbol
    expansion_trials = 0

    while len(nonterminals(term)) > 0:
        symbol_to_expand = random.choice(nonterminals(term))
        expansions = grammar[symbol_to_expand]
        expansion = random.choice(expansions)
        # In later chapters, we allow expansions to be tuples,
        # with the expansion being the first element
        if isinstance(expansion, tuple):
            expansion = expansion[0]

        new_term = term.replace(symbol_to_expand, expansion, 1)

        if len(nonterminals(new_term)) < max_nonterminals:
            term = new_term
            if log:
                print("%-40s" % (symbol_to_expand + " -> " + expansion), term)
            expansion_trials = 0
        else:
            expansion_trials += 1
            if expansion_trials >= max_expansion_trials:
                raise Exception("Cannot expand " + repr(term))

    return term

def json_test(func: Callable) -> Callable:
    json_func = func
    def json_run(seed_str: str) -> bool:
        try:
            json_func(seed_str)
        except Exception as e:
            raise ValueError("Result status is invalid")
        try:
            json.dumps(seed_str)
        except Exception as e:
            raise ValueError("Result status is invalid")
        return True
    return json_run

def print_stats(population: list[Seed], name: str) -> None:
    error, invalid, valid = 0, 0, 0
    for seed in population:
        try:
            dj.loads(seed.data)
            print(f"VALID | Coverage: {len(seed.coverage)} | Seed: {seed.data}")
            valid += 1
        except dj.Error as e:
            invalid += 1
            print(f"INVALID: {e} | Coverage: {len(seed.coverage)} | Seed: {seed.data}")
        except Exception as e:
            error += 1
            print(f"ERROR: {e} | Coverage: {len(seed.coverage)} | Seed: {seed.data}")
    print(f"{name} TOTAL: {len(population)} VALID: {valid} | INVALID: {invalid} | ERROR: {error}")

if __name__ == '__main__':
    biggest_json, try_count = '', 0
    while not biggest_json or try_count < 50:
        try:
            tmp_json = simple_grammar_fuzzer(JSON_GRAMMAR, max_nonterminals=15)
            if len(tmp_json) > len(biggest_json):
                biggest_json = tmp_json
        except Exception:
            continue
        try_count += 1

    chars = ''.join(CHARSET)
    mutator = StringMutator(chars)
    trials = 100000
    seeds = [biggest_json]
    json_test_func = json_test(dj.loads)

    pw_gdf_schedule = PowerSchedule()
    runner_cgf_afl = FunctionCoverageRunner(json_test_func)
    cgf_afl = GreyboxFuzzer(seeds=seeds, mutator=mutator, schedule=pw_gdf_schedule)
    cgf_afl.runs(runner=runner_cgf_afl, trials=trials)
    print_stats(cgf_afl.population, f"{type(cgf_afl).__name__} {type(pw_gdf_schedule).__name__}")


