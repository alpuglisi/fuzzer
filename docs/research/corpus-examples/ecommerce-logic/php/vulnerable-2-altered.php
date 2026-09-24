<?php
// vulnerable-2-altered.php
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics" -- derived from idiomatic-2-altered.php's own real structure,
// altered ONLY in how the discount percentage is decided: the client's
// own posted `vip_discount_percent` field is trusted outright instead of
// looking it up from the customer's own stored loyalty_tier column.

function applyLoyaltyDiscount(PDO $pdo, int $customerId, float $orderTotal): array
{
    $stmt = $pdo->prepare('SELECT loyalty_tier FROM customers WHERE id = ?');
    $stmt->execute([$customerId]);
    $tier = $stmt->fetchColumn();

    // Business-logic flaw: the discount percentage applied is whatever
    // the client claims in $_POST['vip_discount_percent'] -- no lookup
    // against the customer's own tier, no upper bound (a percent over
    // 100 drives the total negative), and no allowlist of the tiers'
    // own known valid percentages.
    $discountPercent = (float) ($_POST['vip_discount_percent'] ?? 0);
    $discountedTotal = round($orderTotal * (1 - $discountPercent), 2);

    return [
        'tier' => $tier,
        'discount_percent' => $discountPercent,
        'total' => $discountedTotal,
    ];
}
