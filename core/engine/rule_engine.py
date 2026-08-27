"""Rule engine: loads YAML detection rules and evaluates them against Evidence.

Each rule matches on an evidence `type` plus a regex `pattern` tested against
the evidence's `value`. A successful match produces a `Match`, carrying the
rule's confidence and the version of the ruleset it came from.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Union

import yaml

from core.engine.evidence import Evidence


DEFAULT_RULESET_VERSION = "0.0.0-dev"


class RuleEngineError(Exception):
    """Raised when a ruleset directory or an individual rule is malformed."""


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    match_type: str
    pattern: str
    confidence: float
    compiled: re.Pattern = field(repr=False, compare=False)


@dataclass(frozen=True)
class Match:
    rule_id: str
    evidence: Evidence
    confidence: float
    ruleset_version: str


class RuleEngine:
    """Loads YAML rules from a directory and evaluates them against Evidence."""

    def __init__(self, ruleset_dir: Union[str, Path]):
        self.ruleset_dir = Path(ruleset_dir)
        self.version = DEFAULT_RULESET_VERSION
        self.rules: List[Rule] = []
        self._load()

    def _load(self) -> None:
        if not self.ruleset_dir.is_dir():
            raise RuleEngineError(f"Ruleset directory not found: {self.ruleset_dir}")

        meta_path = self.ruleset_dir / "meta.yaml"
        if meta_path.is_file():
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = yaml.safe_load(f) or {}
            self.version = str(meta.get("version", DEFAULT_RULESET_VERSION))

        rule_files = sorted(self.ruleset_dir.glob("*.yaml")) + sorted(
            self.ruleset_dir.glob("*.yml")
        )

        for path in rule_files:
            if path.name in ("meta.yaml", "meta.yml"):
                continue

            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)

            for entry in self._coerce_entries(raw):
                self.rules.append(self._parse_rule(entry, path))

    @staticmethod
    def _coerce_entries(raw) -> List[dict]:
        """A rule file may contain one rule, a bare list, or {rules: [...]}."""
        if raw is None:
            return []
        if isinstance(raw, list):
            return raw
        if isinstance(raw, dict) and "rules" in raw:
            return raw["rules"]
        if isinstance(raw, dict):
            return [raw]
        return []

    @staticmethod
    def _parse_rule(entry: dict, path: Path) -> Rule:
        try:
            rule_id = entry["id"]
            description = entry.get("description", "")
            match = entry["match"]
            match_type = match["type"]
            pattern = match["pattern"]
            confidence = float(entry["confidence"])
        except (KeyError, TypeError) as e:
            raise RuleEngineError(f"Malformed rule in {path}: {e}")

        if not (0.0 <= confidence <= 1.0):
            raise RuleEngineError(
                f"Rule '{rule_id}' in {path} has out-of-range confidence: {confidence}"
            )

        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            raise RuleEngineError(f"Invalid regex in rule '{rule_id}' ({path}): {e}")

        return Rule(
            id=rule_id,
            description=description,
            match_type=match_type,
            pattern=pattern,
            confidence=confidence,
            compiled=compiled,
        )

    def evaluate(self, evidence_list: List[Evidence]) -> List[Match]:
        """Evaluate every rule against every piece of evidence, in order."""
        matches: List[Match] = []

        for evidence in evidence_list:
            for rule in self.rules:
                if rule.match_type != evidence.type:
                    continue
                if rule.compiled.search(evidence.value):
                    matches.append(
                        Match(
                            rule_id=rule.id,
                            evidence=evidence,
                            confidence=rule.confidence,
                            ruleset_version=self.version,
                        )
                    )

        return matches
