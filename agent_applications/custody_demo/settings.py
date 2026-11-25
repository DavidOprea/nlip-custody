"""Load the demo's config.toml and fill in what depends on generated keys.

The TOML file stays static and readable; this loader adds, per run:

* keys: generated once into ``keys/`` (one Ed25519 key per custody identity) with the
  public halves in ``keys/public.json``;
* ``pinned_keys`` and ``peers`` for every custody SE, from ``[custody.identities]``;
* ``approvers`` (the user client's key) for every tool guard;
* the signer source: ``key_file`` in-process, ``signer`` (separate process) over HTTP;
* absolute paths for keys and logs.

The ``defense`` picks what runs, all built from the same ``config.toml``:

* ``none``: every security pipeline and tool guard removed (baseline 1);
* ``custody``: the custody SE plus the tool guards (the contribution);
* ``custody_nostorage``: the same without storage-author tracking (ablation);
* ``custody_noendorse``: the same without the reader's endorsement (ablation);
* ``per_hop``: the same SEs with no propagation, plus the Rule of Two (baseline 3);
* ``authority``: sender tokens plus warrant caps at the tools (baseline 4);
* ``judge_heuristic`` / ``judge_llm``: a content judge at every door (baseline 2).
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
Defense = Literal["none", "custody", "custody_nostorage", "custody_noendorse", "per_hop",
                  "authority", "judge_heuristic", "judge_llm"]
CUSTODY_VARIANTS = {"custody", "custody_nostorage", "custody_noendorse"}
DEFENSES: tuple[str, ...] = (
    "none", "judge_heuristic", "judge_llm", "per_hop", "authority", "custody_nostorage",
    "custody_noendorse", "custody",
)


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
        defense: Defense = "custody",
        custody: bool | None = None,
        mode: Mode = "inproc",
        log_dir: str | Path | None = None,
        config_path: Path = CONFIG_PATH,
    ) -> None:
        if custody is not None:  # backwards-compatible on/off switch
            defense = "custody" if custody else "none"
        if defense not in DEFENSES:
            raise ValueError(f"Unknown defence {defense!r}; choose from {', '.join(DEFENSES)}.")
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)
        base = config_path.parent
        self.defense = defense
        self.mode = mode
        section = raw["custody"]
        self.identities: dict[str, str] = dict(section["identities"])
        self.keys_dir = (base / section["keys_dir"]).resolve()
        self.log_dir = Path(log_dir).resolve() if log_dir else (base / section["log_dir"]).resolve()
        self.public_keys = ensure_keys(self.keys_dir, list(self.identities.values()))
        self.user_identity = self.identities["user"]
        self.baselines = raw.get("baselines", {})
        self.config = self._build(raw)
        self.guards: dict[str, tuple[type, dict[str, Any]]] = self._guards(raw)

    @property
    def custody(self) -> bool:
        """Signed sender tokens and a per-task store (custody and the token baselines)."""
        return self.defense in CUSTODY_VARIANTS | {"per_hop", "authority"}

    @property
    def consent(self) -> bool:
        """Whether a blocked call can be released by the user's one-time consent."""
        return self.defense in CUSTODY_VARIANTS | {"per_hop"}

    @property
    def signers(self) -> bool:
        return self.custody

    # -------------------------------------------------------------- building

    def _path(self, value: str, *, log: bool = False) -> str:
        if log:
            return str(self.log_dir / Path(value).name)
        return str((self.keys_dir.parent / value).resolve())

    def _build(self, raw: dict[str, Any]) -> dict[str, Any]:
        config = copy.deepcopy(raw)
        if self.defense == "none":
            for entity in config["entities"].values():
                entity.pop("security", None)
            config["security_extensions"] = {}
            return config
        if self.defense.startswith("judge_"):
            judge = self.baselines["judge"]
            config["security_extensions"] = {"content_judge": {
                "entrypoint": judge["entrypoint"],
                "options": {"detector": self.defense.removeprefix("judge_"),
                            **({"model": judge["model"]} if "model" in judge else {})},
            }}
            for entity in config["entities"].values():
                if "security" in entity:
                    entity["security"] = {"ingress": ["content_judge"], "egress": ["content_judge"]}
            return config
        for definition in config.get("security_extensions", {}).values():
            options = definition.setdefault("options", {})
            identity = options["identity"]
            if self.defense == "per_hop":
                per_hop = self.baselines["per_hop"]
                definition["entrypoint"] = per_hop["entrypoint"]
                options["sensitive_sources"] = list(per_hop.get("sensitive_sources", []))
                options["outside_destinations"] = list(per_hop.get("outside_destinations", []))
                options.pop("endorse", None)  # per-hop has no endorsement
            elif self.defense == "authority":
                options["propagate"] = False
            elif self.defense == "custody_noendorse" and "endorse" in options:
                options["endorse_enabled"] = False
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

    def _guards(self, raw: dict[str, Any]) -> dict[str, tuple[type, dict[str, Any]]]:
        if self.defense in CUSTODY_VARIANTS | {"per_hop"}:
            guards = {name: (CustodyToolGuard, self._guard_options(opts))
                      for name, opts in raw.get("custody_guard", {}).items()}
            if self.defense == "custody_nostorage":
                for _, opts in guards.values():
                    opts["track_storage"] = False
            return guards
        if self.defense == "authority":
            from security_extensions.baselines.authority import AuthorityGuard

            out = {}
            for name, section in self.baselines.get("authority", {}).items():
                opts = {"identity": self.identities[name],
                        "warrants": copy.deepcopy(section["warrants"])}
                log = raw.get("custody_guard", {}).get(name, {}).get("log_path")
                if log:
                    opts["log_path"] = self._path(log, log=True)
                out[name] = (AuthorityGuard, opts)
            return out
        return {}

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
        entry = self.guards.get(entity)
        if entry is None:
            return None
        cls, options = entry
        return cls.from_config(options, store=store)

    def signer_address(self, identity: str) -> str:
        for definition in self.config["security_extensions"].values():
            if definition["options"]["identity"] == identity:
                return definition["options"]["signer"]
        raise KeyError(identity)
