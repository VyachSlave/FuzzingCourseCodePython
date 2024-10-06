import os
import subprocess
from typing import Callable, Tuple, Any

from fuzzingbook.Fuzzer import Fuzzer, Runner, Outcome

import random
import networkx as nx

from ControlFlow import maze, target_tile, generate_maze_code, get_callgraph

from fuzzingbook.MutationFuzzer import FunctionCoverageRunner, MutationCoverageFuzzer
from fuzzingbook.GreyboxFuzzer import AdvancedMutationFuzzer, GreyboxFuzzer, Mutator, PowerSchedule, Seed, \
    AFLGoSchedule, CountingGreyboxFuzzer, AFLFastSchedule

"""
Реализовать мутатор для лабиринта
• append
• delete_last_character
• insert

Реализовать мутатор, по типу StringMutate

Реализовать функцию printStats (INVALID, VALID, SOLVED) и кол-во раз
• Построить call graph для сгенерированного кода и предподсчитать все дистанции
• Реализовать стратегию Directed фаззинга
• Опробовать все виды фаззеров, построить соответствующие графики

Попробовать Black Box Fuzzer, Gray Box Fuzzer
Проверить в какие состояния и сколько раз они заходят за 10000 раз
Убедиться что стратегия Directed Fuzzing является наиболее оптимальной

Нашел код идентичный Java | https://www.fuzzingbook.org/html/Fuzzer.html
"""

maze_string = """
+-+-----+
|X|     |
| | --+ |
| |   | |
| +-- | |
|     |#|
+-----+-+
"""

class StringMutator(Mutator):
    def __init__(self, chars: str) -> None:
        super().__init__()
        self._chars = list(chars)
        self.mutators = [self.append_char, self.insert_randomly_char, self.delete_last_char]

    def __call__(self, seed_str: str) -> str:
        return self.mutate(seed_str)

    def choose_random_char(self):
        return random.choice(self._chars)

    def append_char(self, seed_str: str) -> str:
        return seed_str + self.choose_random_char()

    def delete_last_char(self, seed_str: str) -> str:
        return seed_str[:len(seed_str) - 1]

    def insert_randomly_char(self, seed_str: str) -> str:
        index = random.randint(0, len(seed_str) - 1)
        return seed_str[:index] + self.choose_random_char() + seed_str[index:]

    def mutate(self, seed_str: str) -> str:
        if len(seed_str) == 0:
            action = self.append_char
        else:
            action = random.choice(self.mutators)
        return action(seed_str)

class BlackBoxFuzzer(AdvancedMutationFuzzer):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.coverages_seen = set()

    def run(self, runner: FunctionCoverageRunner = Runner()) -> Tuple[subprocess.CompletedProcess, Outcome]:
        result, outcome = runner.run(self.fuzz())
        new_coverage = frozenset(runner.coverage())
        if new_coverage not in self.coverages_seen:
            seed = Seed(self.inp)
            self.coverages_seen.add(new_coverage)
            self.population.append(seed)
        return result, outcome

class BlackBoxMutationFuzzer(MutationCoverageFuzzer):
    def __init__(self, mutator: Mutator, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.mutator = mutator
        self.seed_answ = []

    def mutate(self, inp: str) -> str:
        return self.mutator.mutate(inp)

    def run(self, runner: FunctionCoverageRunner) -> Any:
        result, outcome = Fuzzer.run(self, runner)
        new_coverage = frozenset(runner.coverage())
        if new_coverage not in self.coverages_seen:
            self.population.append(self.inp)
            self.coverages_seen.add(new_coverage)
            seed = Seed(self.inp)
            self.seed_answ.append(seed)
        return result

def maze_test(func: Callable) -> Callable:
    maze_func = func
    def maze_run(seed_str: str) -> bool:
        result = maze_func(seed_str)
        first_line = result.splitlines()[0]
        if first_line == "INVALID":
            raise ValueError("Result status is invalid")

        return True
    return maze_run


def print_stats(population: list[Seed], name: str) -> None:
    total = len(population)
    solved, invalid, valid = 0, 0, 0
    for seed in population:
        s = maze(str(seed.data))
        if "INVALID" in s:
            invalid += 1
        elif "VALID" in s:
            valid += 1
        elif "SOLVED" in s:
            solved += 1
    print(f"{name} TOTAL: {total} | SOLVED: {solved} | VALID: {valid} | INVALID: {invalid}")

def get_distance(cg) -> dict:
    distance = {}
    target = target_tile()
    for node in cg.nodes():
        if target in node:
            target_node = node
            break
    else:
        return distance
    for node in cg.nodes():
        if "__" in node:
            name = node.split("__")[-1]
        else:
            name = node
        try:
            distance[name] = nx.shortest_path_length(cg, node, target_node)
        except:
            distance[name] = 0xFFFF
    return distance


if __name__ == "__main__":
    maze_code = generate_maze_code(maze_string)
    exec(maze_code)
    cg = get_callgraph(maze_code)
    distance = get_distance(cg)

    chars = "UDLR"
    mutator = StringMutator(chars)
    maze_test_func = maze_test(maze)
    seeds = [" "]
    trials = 10000

    mcf = BlackBoxMutationFuzzer(seed=seeds, mutator=mutator)
    maze_runner_mcf = FunctionCoverageRunner(maze_test_func)
    mcf.runs(runner=maze_runner_mcf, trials=trials)
    print_stats(mcf.seed_answ, type(mcf).__name__)

    pw_amcf_schedule = PowerSchedule()
    maze_runner_amcf_pw = FunctionCoverageRunner(maze_test_func)
    amcf = BlackBoxFuzzer(seeds=seeds, mutator=mutator, schedule=pw_amcf_schedule)
    amcf.runs(runner=maze_runner_amcf_pw, trials=trials)
    print_stats(amcf.population, f"{type(amcf).__name__} {type(pw_amcf_schedule).__name__}")

    pw_gdf_schedule = PowerSchedule()
    maze_runner_gbf_pw = FunctionCoverageRunner(maze_test_func)
    gbf_pw = GreyboxFuzzer(seeds=seeds, mutator=mutator, schedule=pw_gdf_schedule)
    gbf_pw.runs(runner=maze_runner_gbf_pw, trials=trials)
    print_stats(gbf_pw.population, f"{type(gbf_pw).__name__} {type(pw_gdf_schedule).__name__}")

    afl_cgf_schedule = AFLFastSchedule(0.5)
    maze_runner_cgf_afl = FunctionCoverageRunner(maze_test_func)
    cgf_afl = CountingGreyboxFuzzer(seeds=seeds, mutator=mutator, schedule=afl_cgf_schedule)
    cgf_afl.runs(runner=maze_runner_cgf_afl, trials=trials)
    print_stats(cgf_afl.population, f"{type(gbf_pw).__name__} {type(afl_cgf_schedule).__name__}")

    maze_runner_gbf_afl = FunctionCoverageRunner(maze_test_func)
    afl_gdf_schedule = AFLGoSchedule(distance=distance, exponent=5)
    gdf_afl = GreyboxFuzzer(seeds=seeds, mutator=mutator, schedule=afl_gdf_schedule)
    gdf_afl.runs(runner=maze_runner_gbf_afl, trials=trials)
    print_stats(gdf_afl.population, f"{type(gdf_afl).__name__} {type(afl_gdf_schedule).__name__}")

    if os.path.exists('callgraph.dot'):
        os.remove('callgraph.dot')

    if os.path.exists('callgraph.py'):
        os.remove('callgraph.py')