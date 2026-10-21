"""Root of the conformance test package.

Declaring ``tests`` as a package makes every in-repo import fully qualified
(``tests.sovereign.fixtures``, ``tests.abide.*``, ``tests.harness.*``) so the
repo root on ``pythonpath`` is the single canonical resolution path -- no
per-conftest sys.path mutation, no namespace ambiguity.
"""
