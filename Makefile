.PHONY: setup test stan shell

DC = docker compose

setup:
	$(DC) build
	$(DC) run --rm app composer install

test:
	$(DC) run --rm app ./vendor/bin/phpunit

stan:
	$(DC) run --rm app ./vendor/bin/phpstan analyse src --level=8

shell:
	$(DC) run --rm app sh
