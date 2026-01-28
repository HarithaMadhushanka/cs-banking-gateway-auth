FROM php:8.4-cli

RUN apt-get update && apt-get install -y \
    git unzip libzip-dev \
  && docker-php-ext-install pdo_mysql \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
CMD ["sh", "-lc", "php -S 0.0.0.0:9000 -t public"]
