from pathlib import Path

from scamcheck.evals import load_dataset, run_eval, score, to_markdown

DATASET = Path(__file__).parent.parent / "evals" / "dataset.jsonl"


def test_dataset_is_well_formed():
    cases = load_dataset(DATASET)
    assert len(cases) >= 40
    assert len({c["id"] for c in cases}) == len(cases)
    assert {c["label"] for c in cases} == {"scam", "legit"}
    assert all(c["message"].strip() for c in cases)
    # adversarial cases stay in the set
    assert sum("ADVERSARIAL" in c["notes"] for c in cases) >= 3


class ScriptedAgent:
    """Returns a fixed verdict per message so we can test scoring end to end."""

    answers = {"scam-a": "likely_scam", "scam-b": "likely_legitimate", "legit-a": "likely_scam"}

    def __init__(self):
        self.usage = {"tool_calls": 3, "input_tokens": 1000, "output_tokens": 500}

    def check(self, message):
        yield {
            "type": "verdict",
            "verdict": {"verdict": self.answers.get(message, "likely_legitimate")},
        }


CASES = [
    {"id": "1", "label": "scam", "category": "x", "notes": "", "message": "scam-a"},
    {"id": "2", "label": "scam", "category": "x", "notes": "", "message": "scam-b"},
    {"id": "3", "label": "legit", "category": "x", "notes": "", "message": "legit-a"},
    {"id": "4", "label": "legit", "category": "x", "notes": "", "message": "legit-b"},
]


def test_scoring_end_to_end():
    rows = run_eval(CASES, mode="agent", agent_factory=ScriptedAgent, workers=2)
    m = score(rows, model="claude-opus-5-5")
    assert m["scam_detection_rate"] == 0.5
    assert m["false_legitimate_rate"] == 0.5
    assert m["false_alarm_rate"] == 0.5
    assert m["legit_cleared_rate"] == 0.5
    assert m["mean_tool_calls"] == 3
    # 4 * (1000 * $4 + 500 * $20) / 1M
    assert m["est_cost_usd"] == 0.056
    md = to_markdown(m, rows, "test")
    assert "`2` (scam" in md and "`3` (legit" in md


def test_crashing_case_is_recorded_not_raised():
    class Boom:
        usage = {}

        def check(self, message):
            raise RuntimeError("down")

    rows = run_eval(CASES[:1], mode="agent", agent_factory=Boom)
    assert rows[0]["verdict"] == "error"
    assert score(rows)["errors"] == 1
