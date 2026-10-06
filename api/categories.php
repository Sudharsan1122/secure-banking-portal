<?php
/**
 * Categories Listing API Endpoint
 * 
 * PILLAR B [B1]: TRANSACTION CATEGORIES
 * 
 * Lists all predefined transaction categories with their associated icons and visual color accents.
 */

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../security/security_headers.php';
require_once __DIR__ . '/../security/auth.php';
require_once __DIR__ . '/../security/validation.php';
require_once __DIR__ . '/../config/database.php';

require_method('GET');
guard_parameter_pollution();

$currentUser = require_auth();

try {
    $pdo = get_db();
    $stmt = $pdo->query("SELECT id, name, icon, color FROM categories ORDER BY name ASC");
    $categories = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $formatted = [];
    foreach ($categories as $cat) {
        $formatted[] = [
            'id'    => (int)$cat['id'],
            'name'  => safe_html($cat['name']),
            'icon'  => safe_html($cat['icon'] ?? 'tag'),
            'color' => safe_html($cat['color'] ?? '#6b7280')
        ];
    }

    echo json_encode([
        'status' => 'success',
        'data'   => $formatted
    ]);

} catch (Throwable $e) {
    error_log("Categories API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to fetch categories.']);
}
