SHELL := /bin/bash

.PHONY: git deploy

git:
	@read -r -p "Commit message: " msg; \
	msg=$${msg:-update}; \
	git add -A && \
	git commit -m "$$msg" && \
	(git push || git push --set-upstream origin HEAD)

deploy:
	@./deploy.sh
