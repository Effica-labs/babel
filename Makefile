SHELL := /bin/bash

.PHONY: git test deploy backup

git:
	@read -r -p "Commit message: " msg; \
	msg=$${msg:-update}; \
	git add -A && \
	git commit -m "$$msg" && \
	(git push || git push --set-upstream origin HEAD)

test:
	@go test ./...

deploy: test
	@./deploy.sh

backup:
	@mkdir -p backups
	@stamp=$$(date +%Y%m%d-%H%M%S); \
	ssh pi 'sqlite3 ~/babel/babel.db ".backup /tmp/babel-backup.db"' && \
	scp pi:/tmp/babel-backup.db "backups/babel-$$stamp.db" && \
	scp pi:babel/babel.env "backups/babel-$$stamp.env" && \
	ssh pi 'rm -f /tmp/babel-backup.db'
