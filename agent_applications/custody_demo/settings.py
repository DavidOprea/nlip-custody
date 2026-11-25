"""Load the demo's config.toml and fill in what depends on generated keys.

The TOML file stays static and readable; this loader adds, per run:

* keys: generated once into ``keys/`` (one Ed25519 key per custody identity) with the
  public halves in ``keys/public.json``;
* ``pinned_keys`` and ``peers`` for every custody SE, from ``[custody.identities]``;
* ``approvers`` (the user client's key) for every tool guard;
* the signer source: ``key_file`` in-process, ``signer`` (separate process) over HTTP;
* absolute paths for keys and logs.

With ``custody=False`` every entity's security pipeline and every tool guard is
removed, which is baseline 1 (no security extension).
"""

from __future__ import annotations

import copy
import json
import tomllib
from pathlib import Path
from typing import Any, Literal

from nlip_sdk.nlip_security_extensions import SecurityExtensionManager
from security_extensions.custody.guard import CustodyToolGuard
from security_extensions.custody.keys import (
    generate_private_key,
    load_private_key,
    public_key_b64,
)
from security_extensions.custody.store import CustodyStore

APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "config.toml"
Mode = Literal["inproc", "http"]


def key_filename(identity: str) -> str:
    return identity.replace(":", "_").replace("/", "_") + ".pem"


def ensure_keys(keys_dir: Path, identities: list[str]) -> dict[str, str]:
    """Create missing keys; return ``{identity: b64url public key}``."""
    keys_dir.mkdir(parents=True, exist_ok=True)
    public: dict[str, str] = {}
    for identity in identities:
        path = keys_dir / key_filename(identity)
        key = load_private_key(path) if path.exists() else generate_private_key(path)
        public[identity] = public_key_b64(key)
    (keys_dir / "public.json").write_text(json.dumps(public, indent=2) + "\n")
    return public


class DemoSettings:
    def __init__(
        self,
        *,
        custody: bool = True,
        mode: Mode = "inproc",
        log_dir: str | Path | None = None,
        config_path: Path = CONFIG_PATH,
    ) -> None:
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)
        base = config_path.parent
        self.custody = custody
        self.mode = mode
        section = raw["custody"]
        self.identities: dict[str, str] = dict(section["identities"])
        self.keys_dir = (base / section["keys_dir"]).resolve()
        self.log_dir = Path(log_dir).resolve() if log_dir else (base / section["log_dir"]).resolve()
        self.public_keys = ensure_keys(self.keys_dir, list(self.identities.values()))
        self.user_identity = self.identities["user"]
        self.config = self._build(raw)
        self.guards: dict[str, dict[str, Any]] = (
            {name: self._guard_options(opts) for name, opts in raw.get("custody_guard", {}).items()}
            if custody
            else {}
        )

    # -------------------------------------------------------------- building

    def _path(self, value: str, *, log: bool = False) -> str:
        if log:
            return str(self.log_dir / Path(value).name)
        return str((self.keys_dir.parent / value).resolve())

    def _build(self, raw: dict[str, Any]) -> dict[str, Any]:
        config = copy.deepcopy(raw)
        if not self.custody:
            for entity in config["entities"].values():
                entity.pop("security", None)
            config["security_extensions"] = {}
            return config
        for definition in config.get("security_extensions", {}).values():
            options = definition.setdefault("options", {})
            identity = options["identity"]
            if self.mode == "inproc":
                options.pop("signer", None)
                options["key_file"] = self._path(options["key_file"])
            else:
                options.pop("key_file", None)
            if "log_path" in options:
                options["log_path"] = self._path(options["log_path"], log=True)
            options["pinned_keys"] = {
                ident: key for ident, key in self.public_keys.items() if ident != identity
            }
            options["peers"] = {
                name: ident for name, ident in self.identities.items()
                if ident != identity and name != "user"
            }
        return config

    def _guard_options(self, options: dict[str, Any]) -> dict[str, Any]:
        options = copy.deepcopy(options)
        if "log_path" in options:
            options["log_path"] = self._path(options["log_path"], log=True)
        options["approvers"] = {self.user_identity: self.public_keys[self.user_identity]}
        return options

    # --------------------------------------------------------------- access

    def entity(self, name: str) -> dict[str, Any]:
        return self.config["entities"][name]

    def endpoints(self, exclude: str) -> dict[str, str]:
        return {
            name: entity["endpoint"]
            for name, entity in self.config["entities"].items()
            if "endpoint" in entity and name != exclude
        }

    def security(self, entity: str) -> SecurityExtensionManager:
        """The entity's pipelines, loaded by the framework from the config."""
        return SecurityExtensionManager.from_config(self.config, entity=entity)

    def guard(self, entity: str, store: CustodyStore | None) -> CustodyToolGuard | None:
        options = self.guards.get(entity)
        if options is None:
            return None
        return CustodyToolGuard.from_config(options, store=store)

    def signer_address(self, identity: str) -> str:
        for definition in self.config["security_extensions"].values():
            if definition["options"]["identity"] == identity:
                return definition["options"]["signer"]
        raise KeyError(identity)
