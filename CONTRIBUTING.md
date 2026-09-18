# Contributing to acc-mcp

Thank you for your interest in contributing! This document outlines the process.

## Language Policy

ALL public artifacts (PR titles/bodies, commits, issues, comments) MUST be in English. Internal notes can be PT-BR.

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`pytest`)
5. Commit with clear, descriptive messages
6. Open a PR with a clear description

## Development Setup

```bash
git clone https://github.com/yunaremaia/acc-mcp.git
cd acc-mcp
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Code Style

- Python 3.11+
- Pydantic v2 for models
- Type hints everywhere
- Tests for all new features

## Code of Conduct

Be respectful. This is an open-source project — kindness matters.
