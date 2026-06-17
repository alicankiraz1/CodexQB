.PHONY: check test export-sanitized

check:
    bash scripts/validate.sh

test:
    python3 -m unittest discover -s tests -v

export-sanitized:
    git archive --format=zip --output CodexQB-sanitized.zip HEAD
