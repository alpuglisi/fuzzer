"""Phase 10 T10.5: the multi-target evaluation harness (generalization/transfer)."""

from fuzzlab.core.store import Store
from fuzzlab.harness.multitarget import (TargetSpec, format_transfer, run_targets,
                                         transfer_summary)
from fuzzlab.labels import contract
from fuzzlab.oracle.probe import Probe

GT_DIR = "lab/ground-truth"


class AutoSender:
    """Confirms SQLi via a SQL error on a quote at product/blog_post (like test_auto)."""
    HEADERS = {"Server": "Apache", "X-Powered-By": "PHP/8.3"}

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        if "/product.php" in url or "/blog_post.php" in url:
            if "'" in value or '"' in value:
                return Probe(500, "You have an error in your SQL syntax",
                             headers=dict(self.HEADERS))
            return Probe(200, "<html>product</html>", headers=dict(self.HEADERS))
        if "/search.php" in url:
            return Probe(200, f"<html>Results for {value}</html>",
                         headers=dict(self.HEADERS))
        return Probe(200, "ok", headers=dict(self.HEADERS))


def test_two_scored_targets_generalize(tmp_path):
    gt = contract.load(GT_DIR)
    specs = [
        TargetSpec("lab-a", "http://127.0.0.1:8080", ground_truth=gt,
                   points_source="ground-truth"),
        TargetSpec("lab-b", "http://127.0.0.1:9090", ground_truth=gt,
                   points_source="ground-truth"),
    ]
    with Store(tmp_path / "u.db") as store:
        outcomes = run_targets(specs, store, sender_for=lambda spec: AutoSender())
        assert [o.name for o in outcomes] == ["lab-a", "lab-b"]
        assert all(o.scored for o in outcomes)
        assert all(o.report.tp > 0 for o in outcomes)      # SQLi confirmed on each
        # distinct runs recorded
        assert outcomes[0].run_id != outcomes[1].run_id

        summary = transfer_summary(outcomes)
        assert summary["targets"] == 2
        assert set(summary["found_on"]) == {"lab-a", "lab-b"}
        assert summary["macro_recall"] > 0 and summary["macro_precision"] > 0
        assert summary["generalizes"] is True              # real vulns on >= 2 targets


def test_transfer_handles_unscored_target(tmp_path):
    gt = contract.load(GT_DIR)
    specs = [
        TargetSpec("scored", "http://127.0.0.1:8080", ground_truth=gt,
                   points_source="ground-truth"),
        TargetSpec("unscored", "http://127.0.0.1:9090", ground_truth=None,
                   selected_categories=["sql-injection"], points_source="crawl"),
    ]
    with Store(tmp_path / "u.db") as store:
        outcomes = run_targets(specs, store, sender_for=lambda spec: AutoSender())
        by_name = {o.name: o for o in outcomes}
        assert by_name["scored"].scored is True
        assert by_name["unscored"].scored is False         # no ground truth → unscored
        summary = transfer_summary(outcomes)
        # macro metrics computed over the scored subset only
        assert "macro_recall" in summary
        # one target scored with recall>0 → not enough to claim generalization
        assert summary["generalizes"] is False


def test_format_transfer_text(tmp_path):
    gt = contract.load(GT_DIR)
    specs = [TargetSpec("lab-a", "http://127.0.0.1:8080", ground_truth=gt,
                        points_source="ground-truth")]
    with Store(tmp_path / "u.db") as store:
        outcomes = run_targets(specs, store, sender_for=lambda spec: AutoSender())
        text = format_transfer(transfer_summary(outcomes))
        assert "multi-target transfer over 1 target(s)" in text
        assert "lab-a: tp=" in text and "recall=" in text


def test_no_targets_is_empty_summary(tmp_path):
    with Store(tmp_path / "u.db") as store:
        summary = transfer_summary(run_targets([], store, sender_for=lambda s: None))
        assert summary["targets"] == 0 and summary["found_on"] == []
        assert "macro_recall" not in summary               # nothing scored
