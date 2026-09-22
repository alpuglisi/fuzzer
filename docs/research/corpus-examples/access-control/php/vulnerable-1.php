<?php
/**
 * Trang Chi Tiết Đơn Hàng
 * LỖ HỎNG: IDOR - Không kiểm tra quyền sở hữu đơn hàng
 */
require_once 'config.php';

if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

// ========== ⚠️ VULN_START: IDOR - Không kiểm tra quyền sở hữu ==========
// 👉 Để FIX: Thêm /* trước VULN_START và */ sau VULN_END

$order_id = $_GET['id'] ?? 0;

// LỖ HỎNG IDOR: Không check user_id, ai cũng xem được đơn của người khác
$query = "SELECT o.*, u.username, u.full_name, u.email 
          FROM orders o 
          JOIN users u ON o.user_id = u.id 
          WHERE o.id = $order_id";

$result = mysqli_query($conn, $query);
$order = mysqli_fetch_assoc($result);

if (!$order) {
    die("Đơn hàng không tồn tại!");
}

// ========== ⚠️ VULN_END: IDOR ==========


// ========== 🔒 FIX_START: Kiểm tra quyền sở hữu đơn hàng ==========
// 👉 Để KÍCH HOẠT: Xóa /* trước FIX_START và */ sau FIX_END

/*
$order_id = filter_var($_GET['id'] ?? 0, FILTER_VALIDATE_INT);
if (!$order_id || $order_id <= 0) {
    die("ID đơn hàng không hợp lệ!");
}

$current_user_id = $_SESSION['user_id'];
$is_admin = ($_SESSION['role'] ?? '') === 'admin';

if ($is_admin) {
    $stmt = $conn->prepare("SELECT o.*, u.username, u.full_name, u.email 
                            FROM orders o 
                            JOIN users u ON o.user_id = u.id 
                            WHERE o.id = ?");
    $stmt->bind_param("i", $order_id);
} else {
    $stmt = $conn->prepare("SELECT o.*, u.username, u.full_name, u.email 
                            FROM orders o 
                            JOIN users u ON o.user_id = u.id 
                            WHERE o.id = ? AND o.user_id = ?");
    $stmt->bind_param("ii", $order_id, $current_user_id);
}

$stmt->execute();
$result = $stmt->get_result();
$order = $result->fetch_assoc();
$stmt->close();

if (!$order) {
    die("Không tìm thấy đơn hàng hoặc bạn không có quyền xem!");
}
*/

// ========== 🔒 FIX_END: Kiểm tra quyền sở hữu đơn hàng ==========

// Lấy chi tiết sản phẩm trong đơn
$items_query = "SELECT oi.*, p.name as product_name, p.image 
                FROM order_items oi 
                JOIN products p ON oi.product_id = p.id 
                WHERE oi.order_id = $order_id";
$items_result = mysqli_query($conn, $items_query);
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chi Tiết Đơn Hàng #<?php echo $order['id']; ?> - Fashion Shop</title>
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <?php include 'includes/header.php'; ?>
    
    <div class="container py-5">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1 class="fw-bold mb-0">Chi Tiết Đơn Hàng #<?php echo $order['id']; ?></h1>
            <a href="orders.php" class="btn btn-outline-dark rounded-pill">
                <i class="bi bi-arrow-left me-2"></i>Quay lại
            </a>
        </div>
        
        <div class="alert alert-danger border-0 shadow-sm mb-4">
            <i class="bi bi-shield-exclamation me-2"></i>
            <strong>IDOR Exploited!</strong> Bạn đang xem đơn hàng của: 
            <span class="fw-bold"><?php echo htmlspecialchars($order['full_name']); ?></span> 
            (User: <code><?php echo htmlspecialchars($order['username']); ?></code>)
        </div>
        
        <div class="row g-4">
            <div class="col-lg-8">
                <div class="card border-0 shadow-sm rounded-4 overflow-hidden mb-4">
                    <div class="card-header bg-light py-3 ps-4">
                        <h5 class="fw-bold mb-0">Sản phẩm đã đặt</h5>
                    </div>
                    <div class="table-responsive">
                        <table class="table align-middle mb-0">
                            <thead class="bg-light small text-muted">
                                <tr>
                                    <th class="ps-4">Sản phẩm</th>
                                    <th>Giá</th>
                                    <th>Số lượng</th>
                                    <th class="pe-4 text-end">Thành tiền</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php while ($item = mysqli_fetch_assoc($items_result)): ?>
                                    <tr>
                                        <td class="ps-4 py-3">
                                            <div class="d-flex align-items-center">
                                                <img src="assets/images/<?php echo $item['image'] ?? 'placeholder.jpg'; ?>" 
                                                     class="rounded-3 me-3" style="width: 50px; height: 50px; object-fit: cover;">
                                                <span class="fw-bold small"><?php echo $item['product_name']; ?></span>
                                            </div>
                                        </td>
                                        <td><?php echo number_format($item['price']); ?>đ</td>
                                        <td>x<?php echo $item['quantity']; ?></td>
                                        <td class="pe-4 text-end fw-bold"><?php echo number_format($item['price'] * $item['quantity']); ?>đ</td>
                                    </tr>
                                <?php endwhile; ?>
                            </tbody>
                            <tfoot class="bg-light">
                                <tr>
                                    <td colspan="3" class="ps-4 py-3 fw-bold">Tổng cộng</td>
                                    <td class="pe-4 py-3 text-end fw-bold fs-5 text-primary"><?php echo number_format($order['total_amount']); ?>đ</td>
                                </tr>
                            </tfoot>
                        </table>
                    </div>
                </div>
            </div>
            
            <div class="col-lg-4">
                <div class="card border-0 shadow-sm rounded-4 p-4 mb-4">
                    <h5 class="fw-bold mb-4">Thông tin đơn hàng</h5>
                    <div class="mb-3">
                        <label class="text-muted small d-block">Trạng thái</label>
                        <span class="badge bg-primary rounded-pill px-3 py-2 mt-1">
                            <?php echo $order['status']; ?>
                        </span>
                    </div>
                    <div class="mb-3">
                        <label class="text-muted small d-block">Ngày đặt</label>
                        <span class="fw-bold small"><?php echo date('d/m/Y H:i', strtotime($order['created_at'])); ?></span>
                    </div>
                    <div class="mb-0">
                        <label class="text-muted small d-block">Địa chỉ giao hàng</label>
                        <p class="small mb-0 mt-1"><?php echo nl2br(htmlspecialchars($order['shipping_address'])); ?></p>
                    </div>
                </div>
                
                <div class="card border-0 shadow-sm rounded-4 p-4">
                    <h5 class="fw-bold mb-4">Thông tin khách hàng</h5>
                    <div class="d-flex align-items-center mb-3">
                        <div class="bg-light rounded-circle p-3 me-3">
                            <i class="bi bi-person fs-4"></i>
                        </div>
                        <div>
                            <h6 class="fw-bold mb-0 small"><?php echo htmlspecialchars($order['full_name']); ?></h6>
                            <small class="text-muted"><?php echo htmlspecialchars($order['email']); ?></small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
            <div class="order-info-section">
                <h2>Thông Tin Đơn Hàng</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <strong>Mã đơn:</strong> #<?php echo $order['id']; ?>
                    </div>
                    <div class="info-item">
                        <strong>Ngày đặt:</strong> <?php echo date('d/m/Y H:i', strtotime($order['created_at'])); ?>
                    </div>
                    <div class="info-item">
                        <strong>Khách hàng:</strong> <?php echo $order['full_name']; ?>
                    </div>
                    <div class="info-item">
                        <strong>Email:</strong> <?php echo $order['email']; ?>
                    </div>
                    <div class="info-item">
                        <strong>Trạng thái:</strong> 
                        <span class="status-badge status-<?php echo $order['status']; ?>">
                            <?php 
                            $status_text = [
                                'pending' => 'Chờ xử lý',
                                'processing' => 'Đang xử lý',
                                'shipped' => 'Đang giao',
                                'delivered' => 'Đã giao',
                                'cancelled' => 'Đã hủy'
                            ];
                            echo $status_text[$order['status']] ?? $order['status'];
                            ?>
                        </span>
                    </div>
                    <div class="info-item">
                        <strong>Địa chỉ giao hàng:</strong> <?php echo $order['shipping_address']; ?>
                    </div>
                </div>
            </div>
            
            <div class="order-items-section">
                <h2>Sản Phẩm</h2>
                <table class="order-items-table">
                    <thead>
                        <tr>
                            <th>Sản phẩm</th>
                            <th>Đơn giá</th>
                            <th>Số lượng</th>
                            <th>Thành tiền</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($item = mysqli_fetch_assoc($items_result)): ?>
                            <tr>
                                <td><?php echo $item['product_name']; ?></td>
                                <td><?php echo number_format($item['price']); ?>đ</td>
                                <td><?php echo $item['quantity']; ?></td>
                                <td><?php echo number_format($item['price'] * $item['quantity']); ?>đ</td>
                            </tr>
                        <?php endwhile; ?>
                    </tbody>
                    <tfoot>
                        <tr>
                            <td colspan="3"><strong>Tổng cộng:</strong></td>
                            <td><strong><?php echo number_format($order['total_amount']); ?>đ</strong></td>
                        </tr>
                    </tfoot>
                </table>
            </div>
        </div>
        
        <div class="order-actions">
            <a href="orders.php" class="btn btn-secondary">Quay Lại</a>
        </div>
    </div>
    
    <?php include 'includes/footer.php'; ?>
</body>
</html>
