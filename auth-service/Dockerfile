FROM php:8.4-cli

RUN apt-get update && apt-get install -y \
    git unzip libzip-dev curl \
 && docker-php-ext-install pdo_mysql

RUN curl -sS https://getcomposer.org/installer | php -- \
    --install-dir=/usr/local/bin \
    --filename=composer

WORKDIR /app
