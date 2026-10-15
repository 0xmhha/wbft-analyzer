"""Verify synthetic table oracles using integer hypergeometric weights.

Run directly with Python 3. This deliberately uses neither floating-point
log-factorials nor the Go enumeration/sampling implementation.
"""

import json
from fractions import Fraction
from functools import cache
from math import comb, prod
from pathlib import Path


@cache
def choose(n, k):
    return comb(n, k)


def allocations(columns, total):
    if len(columns) == 1:
        if 0 <= total <= columns[0]:
            yield (total,)
        return
    for n in range(max(0, total - sum(columns[1:])), min(columns[0], total) + 1):
        for rest in allocations(columns[1:], total - n):
            yield (n,) + rest


def probability(table):
    rows = [sum(row) for row in table]
    columns = tuple(map(sum, zip(*table)))
    remaining, denominator, observed = sum(rows), 1, 1
    current = columns
    for row, total in zip(table[:-1], rows[:-1]):
        denominator *= choose(remaining, total)
        observed *= prod(choose(n, k) for n, k in zip(current, row))
        current = tuple(n - k for n, k in zip(current, row))
        remaining -= total

    def weights(index, available):
        if index == len(rows) - 1:
            assert sum(available) == rows[index]
            yield 1
            return
        for row in allocations(available, rows[index]):
            weight = prod(choose(n, k) for n, k in zip(available, row))
            rest = tuple(n - k for n, k in zip(available, row))
            for suffix in weights(index + 1, rest):
                yield weight * suffix

    all_mass, tail_mass, count = 0, 0, 0
    for weight in weights(0, columns):
        count += 1
        all_mass += weight
        if weight <= observed:
            tail_mass += weight
    assert all_mass == denominator, (all_mass, denominator)
    return Fraction(tail_mass, denominator), count


if __name__ == "__main__":
    fixtures = json.loads(Path(__file__).with_name("conditional-tables.json").read_text())
    for fixture in fixtures:
        p, count = probability(fixture["table"])
        assert p == Fraction(fixture["p"]), (fixture, p)
        assert count == fixture["tables"], (fixture, count)
    print(f"{len(fixtures)} synthetic conditional probabilities verified exactly")
