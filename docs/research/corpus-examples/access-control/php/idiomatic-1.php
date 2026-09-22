<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/backend/Database.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$order_id = $_GET['id'] ?? null;

if (!$order_id) {
    die('No order ID provided');
}

try {
    $db = new Database();
    
    // Get order details
    $order = $db->fetchOne(
        "SELECT * FROM orders WHERE id = ? AND user_id = ?", 
        [$order_id, $_SESSION['user_id']]
    );
    
    if (!$order) {
        die('Order not found');
    }
    
    // Get order items
    $orderItems = $db->fetchAll(
        "SELECT oi.*, b.title, b.author, b.front_image 
         FROM order_items oi 
         JOIN books b ON oi.book_id = b.id 
         WHERE oi.order_id = ?", 
        [$order_id]
    );
    
} catch (Exception $e) {
    die('Error: ' . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Order Success - Papernest</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/bootstrap-icons.min.css">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container-fluid">
        <?php include 'components/navbar.php'; ?>
        
        <div class="container my-5">
            <div class="row justify-content-center">
                <div class="col-md-8">
                    <div class="card shadow">
                        <div class="card-body text-center py-5">
                            <div class="text-success mb-4">
                                <i class="bi bi-check-circle" style="font-size: 5rem;"></i>
                            </div>
                            <h1 class="text-success mb-3">Payment Successful!</h1>
                            <p class="lead">Thank you for your order. Your books will be delivered soon.</p>
                            
                            <div class="alert alert-info mt-4">
                                <strong>Order ID:</strong> #<?php echo htmlspecialchars($order_id); ?><br>
                                <strong>Transaction ID:</strong> <?php echo htmlspecialchars($order['paypal_transaction_id']); ?><br>
                                <strong>Date:</strong> <?php echo date('F d, Y', strtotime($order['order_date'])); ?>
                            </div>
                            
                            <hr class="my-4">
                            
                            <h4 class="mb-3">Order Summary</h4>
                            <div class="list-group text-start">
                                <?php foreach ($orderItems as $item): 
                                    $subtotal = $item['price'] * $item['quantity'];
                                ?>
                                <div class="list-group-item">
                                    <div class="row align-items-center">
                                        <div class="col-md-2">
                                            <img src="assets/img/books/<?php echo htmlspecialchars($item['front_image']); ?>.jpg" 
                                                 alt="Book cover" class="img-fluid" style="max-height: 80px;">
                                        </div>
                                        <div class="col-md-6">
                                            <h6 class="mb-1"><?php echo htmlspecialchars($item['title']); ?></h6>
                                            <small class="text-muted">by <?php echo htmlspecialchars($item['author']); ?></small>
                                        </div>
                                        <div class="col-md-2 text-center">
                                            <span class="badge bg-secondary">Qty: <?php echo htmlspecialchars($item['quantity']); ?></span>
                                        </div>
                                        <div class="col-md-2 text-end">
                                            <strong>₱<?php echo number_format($subtotal, 2); ?></strong>
                                        </div>
                                    </div>
                                </div>
                                <?php endforeach; ?>
                                
                                <div class="list-group-item bg-light">
                                    <div class="row">
                                        <div class="col-md-10 text-end">
                                            <strong>Total:</strong>
                                        </div>
                                        <div class="col-md-2 text-end">
                                            <strong class="text-success">₱<?php echo number_format($order['total_amount'], 2); ?></strong>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="mt-4">
                                <a href="index.php" class="btn btn-primary me-2">
                                    <i class="bi bi-house"></i> Back to Home
                                </a>
                                <a href="orders.php" class="btn btn-outline-secondary">
                                    <i class="bi bi-box-seam"></i> View All Orders
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <?php include 'components/footer.php'; ?>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>