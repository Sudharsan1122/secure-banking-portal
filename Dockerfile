# syntax=docker/dockerfile:1.6

# ---------- Stage 1: composer deps ----------
FROM composer:2 AS vendor
WORKDIR /app
COPY composer.json composer.lock* ./
RUN composer install --no-dev --no-interaction --prefer-dist \
      --optimize-autoloader --no-scripts || true

# ---------- Stage 2: runtime ----------
FROM php:8.2-apache AS runtime

# Install extensions
RUN docker-php-ext-install pdo pdo_mysql mysqli \
 && a2enmod headers rewrite \
 && rm -rf /var/lib/apt/lists/*

# PHP production config
COPY docker/php.ini /usr/local/etc/php/conf.d/99-app.ini

# App code
WORKDIR /var/www/html
COPY . /var/www/html
COPY --from=vendor /app/vendor /var/www/html/vendor

# Remove dev artifacts
RUN rm -rf tests/ docs/ .github/ .git/ node_modules/ \
    && chown -R www-data:www-data /var/www/html

# Non-root user
USER www-data

EXPOSE 80

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost/health.php || exit 1

CMD ["apache2-foreground"]
