"""LLM06 — Excessive Agency module.

Targets LLMs configured with tool-calling capability (OpenAI chat completions
with `tools=[...]`, Anthropic Messages with `tools=[...]`, LangChain agents).
Payloads attempt to coerce the LLM into invoking dangerous tools (SSRF via
HTTP fetch, file read, shell exec) under attacker control.

Detection strategy: the operator points the target's tool configuration at a
MockToolServer instance. When the LLM invokes a tool, MockToolServer responds
with a string containing a canary (CANARY_HTTP_FETCH_HIT_M3RL1N, etc.). The
LLM relays that response back to the user; the canary then appears in the
final response text. The single-shot detector picks it up via the payload's
success_signals.

The orchestration is identical to other single-shot modules — the difference
lives in the YAML payload library (signals carry the canary substrings).

If the target does NOT support tool calls, this module degrades to checking
whether the LLM merely *describes* the tool invocation rather than performing
it. Reports from such runs should be flagged operator-side as
"capability-limited" in p3-review.
"""

from __future__ import annotations

from merlin.modules.base import SingleShotModule


class ExcessiveAgencyModule(SingleShotModule):
    owasp_id = "LLM06"
    category = "excessive_agency"
    name = "excessive-agency"
