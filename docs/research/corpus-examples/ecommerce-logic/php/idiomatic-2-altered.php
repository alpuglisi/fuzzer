<?php
// idiomatic-2-altered.php
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics". VIP/loyalty discount-tier application at checkout -- a
// distinct sub-scenario from this file's price-tampering pair
// (vulnerable-1.php/idiomatic-1.php) and from the woocommerce-cart-hook /
// qloapps-booking pairs elsewhere in this file. The discount percentage
// actually applied is always looked up server-side from the customer's
// own stored loyalty_tier column, never taken from the request.

function applyLoyaltyDiscount(PDO $pdo, int $customerId, float $orderTotal): array
{
    $stmt = $pdo->prepare('SELECT loyalty_tier FROM customers WHERE id = ?');
    $stmt->execute([$customerId]);
    $tier = $stmt->fetchColumn();

    $tierDiscounts = [
        'bronze' => 0.0,
        'silver' => 0.05,
        'gold' => 0.10,
        'platinum' => 0.15,
    ];

    $discountPercent = $tierDiscounts[$tier] ?? 0.0;
    $discountedTotal = round($orderTotal * (1 - $discountPercent), 2);

    return [
        'tier' => $tier,
        'discount_percent' => $discountPercent,
        'total' => $discountedTotal,
    ];
}
