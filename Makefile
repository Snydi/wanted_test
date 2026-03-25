.PHONY: setup test clean

DC = docker compose

setup:
	$(DC) build
	$(DC) run --rm app composer install

test:
	$(DC) run --rm app ./vendor/bin/phpunit

clean:
	-$(DC) run --rm app rm -rf /app/vendor
	$(DC) down --rmi all --volumes --remove-orphans
