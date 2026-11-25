"""Endorsement: a sandboxed reader whose schema-checked, control-only output is trusted.

Label creep is Custody's main cost: once a conversation has read the inbox, every
later sensitive action in it carries the mail senders. Endorsement is the release
valve, in the narrow form the design allows:

* the endorsing agent is a **sandboxed reader**: it can read outside content but
  cannot call other agents, so its only output channel is its reply;
* its reply must be **structured** and **validate against a fixed schema** with no
  free text: counts, booleans, enums. An instruction cannot fit through it;
* if the reply validates and every **authority-bearing field** (payee, account,
  amount, recipient: whatever the schema marks) is empty, the reply token carries
  only the *upstream* principals (who asked the reader), not the outside content it
  read. The reader itself still appears, as the endorser;
* otherwise (free text, schema failure, or any authority value present) the reply
  carries the full set, exactly as without endorsement. This is PACT's rule:
  authority-bearing values keep their provenance.

The check runs in the SE at server egress, outside the reader's model. A compromised
reader model can make its own output useless, but cannot make outside content look
endorsed: anything that fails the schema travels with its full provenance.

Config (under the reader's SE options)::

    [security_extensions.custody_reader.options.endorse]
    authority_fields = ["invoice"]
    schema = { type = "object", additionalProperties = false, ... }

The validator supports a deliberately small JSON Schema subset (``type``,
``properties``, ``required``, ``additionalProperties: false``, ``enum``, ``minimum``,
``maximum``, ``pattern``, ``maxLength``, ``items``, ``maxItems``). Free-form strings
are rejected unless they carry an ``enum`` or a ``pattern``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from nlip_sdk import AllowedFormat
from nlip_sdk.nlip_security_extensions import SecurityEvent

from .extension import CustodyExtension

_TYPES = {
    "object": dict, "array": list, "string": str, "boolean": bool, "null": type(None),
}


class SchemaError(ValueError):
    pass


def check_schema(schema: Mapping[str, Any], path: str = "$") -> None:
    """Reject schemas that would let free text through."""
    types = schema.get("type")
    types = [types] if isinstance(types, str) else list(types or [])
    if not types:
        raise SchemaError(f"{path}: every node needs a type.")
    if "object" in types:
        if schema.get("additionalProperties") is not False:
            raise SchemaError(f"{path}: objects must set additionalProperties = false.")
        for name, sub in schema.get("properties", {}).items():
            check_schema(sub, f"{path}.{name}")
    if "array" in types:
        if "items" not in schema or "maxItems" not in schema:
            raise SchemaError(f"{path}: arrays need items and maxItems.")
        check_schema(schema["items"], f"{path}[]")
    if "string" in types and "enum" not in schema and "pattern" not in schema:
        raise SchemaError(f"{path}: strings need an enum or a pattern (no free text).")


def validate(value: Any, schema: Mapping[str, Any], path: str = "$") -> None:
    types = schema.get("type")
    types = [types] if isinstance(types, str) else list(types)
    if not any(_is_type(value, t) for t in types):
        raise SchemaError(f"{path}: expected {'/'.join(types)}.")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaError(f"{path}: not one of the allowed values.")
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, int):
        if "minimum" in schema and value < schema["minimum"]:
            raise SchemaError(f"{path}: below minimum.")
        if "maximum" in schema and value > schema["maximum"]:
            raise SchemaError(f"{path}: above maximum.")
    elif isinstance(value, str):
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise SchemaError(f"{path}: too long.")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            raise SchemaError(f"{path}: does not match its pattern.")
    elif isinstance(value, list):
        if len(value) > schema["maxItems"]:
            raise SchemaError(f"{path}: too many items.")
        for n, item in enumerate(value):
            validate(item, schema["items"], f"{path}[{n}]")
    elif isinstance(value, dict):
        props = schema.get("properties", {})
        extra = set(value) - set(props)
        if extra:
            raise SchemaError(f"{path}: unexpected field(s) {sorted(extra)}.")
        missing = set(schema.get("required", [])) - set(value)
        if missing:
            raise SchemaError(f"{path}: missing field(s) {sorted(missing)}.")
        for name, item in value.items():
            validate(item, props[name], f"{path}.{name}")


def _is_type(value: Any, name: str) -> bool:
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    expected = _TYPES.get(name)
    if expected is None:
        raise SchemaError(f"Unsupported type {name!r}.")
    if expected is str and isinstance(value, bool):
        return False
    return isinstance(value, expected)


class EndorsingCustodyExtension(CustodyExtension):
    """The custody SE of a sandboxed reader; endorses control-only structured replies."""

    def __init__(
        self,
        identity: str,
        *,
        endorse: Mapping[str, Any] | None = None,
        endorse_enabled: bool = True,
        **options: Any,
    ) -> None:
        super().__init__(identity, **options)
        if endorse is None:
            raise ValueError("An endorsing extension needs an endorse = {schema, ...} table.")
        self._schema = dict(endorse["schema"])
        check_schema(self._schema)
        self._authority = tuple(endorse.get("authority_fields", ()))
        for name in self._authority:
            if name not in self._schema.get("properties", {}):
                raise SchemaError(f"Authority field {name!r} is not in the schema.")
        # endorse_enabled=False is the "no endorsement" ablation.
        self.endorse_enabled = endorse_enabled
        self._upstream: dict[str | None, set[str]] = {}

    def _merged(self, event: SecurityEvent, added: set[str]) -> None:
        if event.component == "server":
            self._upstream.setdefault(event.scope, set()).update(added)

    def endorsement(self, message: Any) -> tuple[bool, str]:
        """(endorsed?, why) for one outgoing reply."""
        if not self.endorse_enabled:
            return False, "endorsement disabled"
        if message.format != AllowedFormat.structured or not isinstance(message.content, dict):
            return False, "reply is not structured"
        if any(p.format != AllowedFormat.token for p in message.submessages or []):
            return False, "reply has non-token parts beside the structured content"
        try:
            validate(message.content, self._schema)
        except SchemaError as error:
            return False, f"schema: {error}"
        filled = [f for f in self._authority if message.content.get(f) not in (None, "", [], {})]
        if filled:
            return False, f"authority-bearing field(s) present: {', '.join(filled)}"
        return True, "control-only structured reply"

    def _reply_principals(self, event: SecurityEvent) -> tuple[frozenset[str], str | None]:
        full, _ = super()._reply_principals(event)
        endorsed, why = self.endorsement(event.message)
        if not endorsed or not self._propagate:
            return full, f"not endorsed: {why}"
        upstream = frozenset(self._upstream.get(event.scope, ()))
        return upstream, f"endorsed: {why}; dropped {sorted(full - upstream)}"
