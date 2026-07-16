"""Producer-side helpers for the Bot Insights orchestrator.

Submodules:
  - ``formatting``: stateless number / string / time / SQL-literal
    formatters used by every report type.

Reserved (built up across phases of the producer refactor):
  - ``sql``: per-report SQL builders.
  - ``evidence``: per-report evidence-packet builders.
  - ``orchestrators``: per-report ``run(args, capture) -> wrapper``
    entry points.
  - ``cli``: argparse setup and report-type dispatch.
"""
