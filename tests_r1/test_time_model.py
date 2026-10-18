"""Fines et errores communes contra enumerationem probantur."""
from copy import deepcopy
from fractions import Fraction
import itertools
import random
import unittest

from probentium.contracts import ProbentiumError
from probentium import time_model as tm


def clock(local=None, shared=None, identifier="clock"):
    return {"schema": "testifex.clock-model.v1", "id": identifier,
            "segments": [{"validity": tm.interval(-1000000, 1000000), "fixed_offset_us": "0",
                          "local_error": tm.interval(0, 0) if local is None else local, "shared_errors": shared or []}],
            "basis_refs": [], "rationale": "Explicit synthetic clock assumption", "assumption_id": "synthetic-zero"}


def expression(n, recorded, model=None):
    return tm.reference_time(format(n, "064x"), recorded, clock() if model is None else model)


class TimeModelTests(unittest.TestCase):
    def test_reference_vectors_preserve_open_and_closed_edges(self):
        values = [(tm.interval(0, 10, False, True), "entailed"), (tm.interval(10, 10), "entailed"),
                  (tm.interval(0, 10), "unresolved"), (tm.interval(10, 11), "unresolved"),
                  (tm.interval(-1, 0), "ruled_out"), (tm.interval(10, 11, False, True), "ruled_out")]
        for interval, expected in values:
            with self.subTest(interval=interval):
                self.assertEqual(tm.interval_verdict(interval, "10"), expected)

    def test_same_interpretation_is_zero_distinct_cells_are_not(self):
        first = expression(1, tm.interval(10, 11, True, False))
        second = expression(2, tm.interval(10, 11, True, False))
        self.assertEqual(tm.difference(first, first), tm.interval(0, 0))
        self.assertEqual(tm.difference(first, second), tm.interval(-1, 1, False, False))

    def test_shared_error_cancels_before_bounds(self):
        model = clock(shared=[{"id": "shared", "coefficient": 1, "interval": tm.interval(-100, 100)}])
        first, second = expression(1, tm.interval(0, 0), model), expression(2, tm.interval(5, 5), model)
        self.assertEqual(tm.difference(first, second), tm.interval(5, 5))
        independent = deepcopy(model)
        independent["segments"][0]["shared_errors"][0]["id"] = "independent"
        self.assertEqual(tm.difference(first, expression(2, tm.interval(5, 5), independent)), tm.interval(-195, 205))

    def test_unknown_does_not_cancel_even_for_same_event(self):
        first = tm.reference_time("1" * 64, tm.interval(0, 0), None)
        self.assertIsNone(tm.difference(first, first))
        model = clock()
        model["segments"][0]["local_error"] = None
        first = expression(1, tm.interval(0, 0), model)
        self.assertEqual(tm.ordered_within(first, first, "5")["verdict"], "unknown")

    def test_zero_coefficient_unknown_error_stays_unknown(self):
        model = clock(shared=[{"id": "unknown", "coefficient": 0, "interval": None}])
        self.assertEqual(expression(1, tm.interval(0, 0), model)["status"], "unknown")

    def test_segments_require_whole_cell_in_exactly_one_segment(self):
        model = clock()
        model["segments"][0]["validity"] = tm.interval(0, 10, True, False)
        second = deepcopy(model["segments"][0])
        second["validity"] = tm.interval(10, 20)
        model["segments"].append(second)
        self.assertEqual(expression(1, tm.interval(9, 10, True, False), model)["status"], "known")
        self.assertEqual(expression(1, tm.interval(9, 10), model)["status"], "unknown")
        model["segments"][1]["validity"] = tm.interval(9, 20)
        self.assertEqual(expression(1, tm.interval(9, 9), model)["status"], "unknown")
        self.assertEqual(expression(1, tm.interval(25, 25), model)["status"], "unknown")

    def test_fixed_offset_sign_and_attribution(self):
        model = clock()
        model["segments"][0]["fixed_offset_us"] = "5"
        value = expression(1, tm.interval(10, 11, True, False), model)
        self.assertEqual(tm.bounds(value), tm.interval(5, 6, True, False))
        self.assertEqual(value["assumption_ids"], ["synthetic-zero"])
        del model["assumption_id"]
        with self.assertRaises(ProbentiumError):
            tm.validate_clock_model(model)

    def test_enumerated_closed_models_match_algebraic_extrema(self):
        for ca, cb, alo, blo in itertools.product((-1, 0, 1), (-1, 0, 1), (-1, 0), (1, 2)):
            a_model = clock(tm.interval(-1, 1), [{"id": "x", "coefficient": ca, "interval": tm.interval(-2, 2)}])
            b_model = clock(tm.interval(-1, 1), [{"id": "x", "coefficient": cb, "interval": tm.interval(-2, 2)}])
            actual = tm.difference(expression(1, tm.interval(alo, alo + 1), a_model), expression(2, tm.interval(blo, blo + 1), b_model))
            samples = [b - a + eb - ea + (cb - ca) * x for a, b, ea, eb, x in itertools.product((alo, alo+1), (blo, blo+1), (-1, 1), (-1, 1), (-2, 2))]
            self.assertEqual((int(actual["lo_us"]), int(actual["hi_us"])), (min(samples), max(samples)))
            for width in (0, 1, 5, 20):
                truths = [0 < value <= width for value in samples]
                expected = "entailed" if all(truths) else "ruled_out" if not any(truths) and (max(samples) <= 0 or min(samples) > width or width == 0) else "unresolved"
                self.assertEqual(tm.interval_verdict(actual, str(width)), expected)

    def test_open_edges_match_independent_rational_samples(self):
        for low, high, left, right in itertools.product(range(-1, 2), range(2, 4), (False, True), (False, True)):
            value = tm.interval(low, high, left, right)
            samples = [Fraction(n, 8) for n in range(low * 8, high * 8 + 1) if (n > low*8 or left) and (n < high*8 or right)]
            for width in (1, 2, 3):
                truth = [0 < sample <= width for sample in samples]
                expected = "entailed" if all(truth) else "ruled_out" if not any(truth) else "unresolved"
                self.assertEqual(tm.interval_verdict(value, str(width)), expected)

    def test_widening_cannot_create_entailed_order(self):
        for gap in range(-2, 8):
            base = tm.ordered_within(expression(1, tm.interval(0, 0)), expression(2, tm.interval(gap, gap)), "5")
            wide = tm.ordered_within(expression(1, tm.interval(0, 0), clock(tm.interval(-2, 2))), expression(2, tm.interval(gap, gap), clock(tm.interval(-2, 2))), "5")
            if wide["verdict"] == "entailed":
                self.assertEqual(base["verdict"], "entailed")

    def test_hostile_times_and_digest_changes_are_rejected(self):
        for value in (1, True, "01", "-0", "+1", "1.0", "9" * 5000, "\u202e1"):
            with self.subTest(value=str(value)[:20]):
                with self.assertRaises(ProbentiumError):
                    tm.microseconds(value)
        for value in (tm.interval(1, 0), tm.interval(0, 0, False, True), {**tm.interval(0, 1), "extra": 1}):
            with self.assertRaises(ProbentiumError):
                tm.validate_interval(value)
        value = expression(1, tm.interval(0, 0))
        value["base"]["lo_us"] = "-1"
        with self.assertRaises(ProbentiumError):
            tm.bounds(value)

    def test_seeded_shared_models_match_independent_corner_oracle(self):
        rng = random.Random(58329)
        for _ in range(300):
            a, b = rng.randint(-10, 10), rng.randint(-10, 10)
            width = rng.randint(0, 25)
            coefficients = [rng.choice((-1, 0, 1)) for _ in range(4)]
            bounds = [(rng.randint(-4, -1), rng.randint(1, 4)) for _ in range(2)]
            models = []
            for offset in (0, 2):
                terms = [{"id": "variable-" + str(i), "coefficient": coefficients[offset+i], "interval": tm.interval(*bounds[i])} for i in range(2)]
                models.append(clock(shared=terms))
            expression_a, expression_b = expression(1, tm.interval(a, a), models[0]), expression(2, tm.interval(b, b), models[1])
            corners = [b-a + (coefficients[2]-coefficients[0])*x + (coefficients[3]-coefficients[1])*y for x,y in itertools.product(*bounds)]
            observed = tm.difference(expression_a, expression_b)
            self.assertEqual((int(observed["lo_us"]), int(observed["hi_us"])), (min(corners), max(corners)))
            oracle = "ruled_out" if width == 0 or max(corners) <= 0 or min(corners) > width else "entailed" if min(corners) > 0 and max(corners) <= width else "unresolved"
            self.assertEqual(tm.ordered_within(expression_a, expression_b, str(width))["verdict"], oracle)

    def test_seeded_hostile_clock_fields_raise_only_domain_errors(self):
        rng = random.Random(9236)
        invalid = [None, True, 1.5, [], {}, "", "\x1b[2J", "\ud800"]
        for _ in range(200):
            model = clock()
            paths = [("schema",), ("basis_refs",), ("segments",), ("segments", 0, "fixed_offset_us"), ("segments", 0, "local_error"), ("segments", 0, "shared_errors")]
            path = rng.choice(paths)
            target = model
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = deepcopy(rng.choice(invalid))
            try:
                tm.validate_clock_model(model)
            except ProbentiumError:
                pass
