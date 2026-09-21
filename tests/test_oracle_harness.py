"""End-to-end: the oracle writes findings that the integration harness scores."""

from fuzzlab.core.store import Store
from fuzzlab.harness import integration
from fuzzlab.labels import contract
from fuzzlab.oracle import Candidate, Oracle
from fuzzlab.oracle.probe import Probe

GT_DIR = "lab/ground-truth"


class ConfirmSqliSender:
    """Confirms SQLi via error signature (any quote payload -> a DB error)."""
    def send(self, url, param, value, timing=False):
        if "'" in value or '"' in value:
            return Probe(500, "You have an error in your SQL syntax; check the manual")
        return Probe(200, "ok")


def test_oracle_findings_are_scored_by_the_harness(tmp_path):
    gt = contract.load(GT_DIR)
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("e2e", "h")
        oracle = Oracle(store=store, run_id=run_id)
        # The oracle confirms the SQLi positives and writes findings (sole writer).
        sqli_positives = [c for c in gt.positives() if c.vuln_class == "sqli"]
        for c in sqli_positives:
            oracle.confirm(
                Candidate(url=c.url, param=c.param, method=c.method, vuln_class="sqli"),
                ConfirmSqliSender())

        # The harness reads those findings back as scorable detections.
        detections = integration.detections_from_store(store, run_id)
        keys = {(d.url, d.param, d.vuln_class) for d in detections}
        assert ("/product.php", "id", "sqli") in keys
        assert ("/blog_post.php", "id", "sqli") in keys
        # One finding per confirmed SQLi positive; all oracle-labeled.
        assert len(detections) == len(sqli_positives)
        confidences = {r["confidence"] for r in store.conn.execute(
            "SELECT confidence FROM finding WHERE run_id=?", (run_id,)).fetchall()}
        assert confidences == {"error-signature"}   # not 'timing-only' anymore
