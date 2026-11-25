"""Baseline security extensions Custody is compared against.

Each one is a faithful, simplified stand-in for an approach rival entries and prior
work take. They reuse Custody's plumbing where the rival has the same mechanism
(signed sender tokens, replay cache, tool hooks), so each comparison isolates the one
idea that differs:

* :mod:`.per_hop`: per-agent taint with no propagation (Rule of Two style). Each
  agent knows only what it saw itself.
* :mod:`.authority`: authority narrowing (Warrant style). Checks who is asking and
  whether the request is within delegated caps, not what shaped it.
* :mod:`.judge`: a content judge at every NLIP door (heuristic or LLM).
"""
