"""`python -m scanners.sast [--target ...|--fixture ...]` 진입점."""

from scanners.sast.semgrep_runner import _main

if __name__ == "__main__":
    _main()
