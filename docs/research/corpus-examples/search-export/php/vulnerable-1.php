<?php
// Fragment from TravianZ's gold/finance-log page (a2b2.php).
// Kept minimal per the GPLv3 copyleft-license handling rule (smallest
// illustrative fragment, not a wholesale file copy) -- see this
// directory's manifest.yaml for the full source attribution.
//
// Shape: a multi-branch search/filter box builds a WHERE clause by
// raw string concatenation from a single $_GET['f'] parameter, then
// reuses the same unparameterized $where string across THREE separate
// queries (count, page listing, and a running-balance subquery) --
// the "beyond the trivial case" shape this cell was collecting for:
// one tainted filter value threaded through multiple sinks, not a
// single one-shot concat.

$uid = (int)$session->uid;

// FILTRU + PAGINARE (filter + pagination)
$perPage = 25;
$page = isset($_GET['p']) ? max(1,(int)$_GET['p']) : 1;
$offset = ($page-1)*$perPage;
$f = $_GET['f'] ?? 'all';

$where = "l.uid = $uid";
if ($f === 'in') $where .= " AND l.gold > 0";
elseif ($f === 'out') $where .= " AND l.gold < 0";
elseif ($f === 'gift') $where .= " AND (l.action LIKE '%Gift%' OR l.details LIKE '%gift%' OR l.details LIKE '%Admin%')";
// NOTE: $f only takes the branches above in the vulnerable app's own UI,
// but nothing stops a direct request with an arbitrary $_GET['f'] value
// from reaching this code path unfiltered by any of the three branches --
// the real bug here is that $where is later interpolated raw into SQL
// with no parameter binding, so any future branch (or a change to how
// $f is validated) inherits a raw-concat sink.

$countRes = mysqli_query($database->dblink, "SELECT COUNT(*) as c FROM " . TB_PREFIX . "gold_fin_log l WHERE $where");
$totalRows = (int)mysqli_fetch_assoc($countRes)['c'];

$q = mysqli_query($database->dblink,
    "SELECT l.*, v.name as vname
     FROM " . TB_PREFIX . "gold_fin_log l
     LEFT JOIN " . TB_PREFIX . "vdata v ON v.wref = l.wid
     WHERE $where
     ORDER BY l.time DESC
     LIMIT $offset, $perPage");

// Same raw $where string reused for a running-balance subquery.
if ($offset > 0) {
    $sumRes = mysqli_query($database->dblink,
        "SELECT COALESCE(SUM(gold),0) as s FROM (
            SELECT gold FROM " . TB_PREFIX . "gold_fin_log l WHERE $where ORDER BY l.time DESC LIMIT $offset
        ) t");
}
