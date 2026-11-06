"""Premium curated DAST rules: the enhanced, high fidelity checks.

These run after the stock engines on the premium profile.  They copy what a
skilled human tester does, and they only report a weakness when the evidence
shows it can be used.  The point is a real, provable finding with an impact
and a fix, never a theory and never a scanner's "this header is missing".

A rule is a declarative spec, not a piece of code.  A fixed engine here reads
the spec and runs it, so an administrator (or the model) can write a rule
without writing Python, and the engine, not the rule's author, is what keeps
every probe inside the safety contract.  See spec.py for the standard every
rule follows, and scope.py for the gate that refuses any host that is not one
of the company's own domains.
"""

from app.core.dast_checks import scope, spec  # noqa: F401
