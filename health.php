<?php
/**
 * Container & Load Balancer Healthcheck Endpoint
 * Returns HTTP 200 with JSON payload when application runtime is healthy.
 */
header('Content-Type: application/json; charset=utf-8');
http_response_code(200);

echo json_encode([
    'status'    => 'healthy',
    'timestamp' => time(),
    'php'       => PHP_VERSION
]);
