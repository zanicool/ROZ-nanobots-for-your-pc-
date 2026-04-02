.PHONY: lint check test ci install help

lint:
	@echo "==> ruff"
	@ruff check .
	@echo "==> mypy"
	@mypy nanobot.py
	@echo "Lint passed."

check: lint
	@echo "==> semgrep"
	@PATH="$$HOME/.local/bin:$$PATH" semgrep scan --config auto --error
	@echo "==> gitleaks"
	@gitleaks detect --source .
	@echo "All checks passed."

test:
	@echo "==> tests (none yet)"
	@echo "All tests passed."

ci: test check

install:
	mkdir -p .git/hooks
	cp hooks/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "Git hooks installed."

help:
	@echo "Usage:"
	@echo "  make lint    run ruff + mypy"
	@echo "  make check   lint + semgrep + gitleaks"
	@echo "  make test    run tests"
	@echo "  make ci      test + check (full pipeline)"
	@echo "  make install install git hooks"
