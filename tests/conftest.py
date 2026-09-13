from hypothesis import settings

# Hypothesis's default on-disk example database lives under `.hypothesis/`
# in the current working directory, which is root-owned inside the Docker
# sandbox (see docker/README.md) -- the same root cause already worked
# around for ruff/mypy's caches. Persisting failing examples across local
# runs isn't needed for this project's test suite, so disable it outright
# rather than pointing it at a writable-but-throwaway path.
settings.register_profile("capaudit", database=None)
settings.load_profile("capaudit")
