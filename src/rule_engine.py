"""
Declarative detection layer for YAML rule files alongside hardcoded rules.
match is a constrained {field, op, value} tree - never eval/exec.
Every hit routes through engine._add_score() so the protected-process floor,
decay, and PID-reuse guard apply to custom rules exactly as to hardcoded ones.
"""

import glob
import logging
import os
import re

import yaml

DEFAULT_RULES_DIR = os.path.join(os.path.dirname(__file__), '..', 'rules', 'custom')

# Sysmon EventID -> the applies_to name a rule author writes in YAML.
EVENT_ID_TO_APPLIES_TO = {
    1: 'process_create',
    10: 'process_access',
    11: 'file_create',
    13: 'registry_event',
}

# Values lowercased at normalization so rule authors never need to think about case.
FIELD_MAP = {
    'process_create': {'Image': 'image', 'ParentImage': 'parent_image', 'CommandLine': 'command_line'},
    'process_access': {'SourceImage': 'source_image', 'TargetImage': 'target_image', 'GrantedAccess': 'granted_access'},
    'file_create': {'Image': 'image', 'TargetFilename': 'target_filename'},
    'registry_event': {'TargetObject': 'target_object'},
}

# Which raw field carries the PID to score, per event type.
PID_FIELD = {
    'process_create': 'ProcessId',
    'process_access': 'SourceProcessId',
    'file_create': 'ProcessId',
    'registry_event': 'ProcessId',
}

VALID_OPS = frozenset({'equals', 'contains', 'in', 'not_in', 'regex', 'gt', 'lt'})
VALID_APPLIES_TO = frozenset(EVENT_ID_TO_APPLIES_TO.values()) | {'static_pe'}


def _to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _field_matches(field_value, op, expected):
    """Match field_value (scalar or list) against expected; any single value satisfying the op returns True."""
    values = field_value if isinstance(field_value, (list, tuple, set)) else [field_value]
    values = [v for v in values if v is not None]
    if not values:
        return False

    if op == 'equals':
        return any(str(v).lower() == str(expected).lower() for v in values)
    if op == 'contains':
        # value may be a list of candidate substrings (field contains ANY of these).
        candidates = expected if isinstance(expected, (list, tuple)) else [expected]
        return any(str(c).lower() in str(v).lower() for c in candidates for v in values)
    if op == 'in':
        expected_list = expected if isinstance(expected, (list, tuple)) else [expected]
        expected_lower = {str(e).lower() for e in expected_list}
        return any(str(v).lower() in expected_lower for v in values)
    if op == 'not_in':
        return not _field_matches(field_value, 'in', expected)
    if op == 'regex':
        return any(re.search(str(expected), str(v), re.IGNORECASE) for v in values)
    if op == 'gt':
        return any(_to_float(v) is not None and _to_float(v) > float(expected) for v in values)
    if op == 'lt':
        return any(_to_float(v) is not None and _to_float(v) < float(expected) for v in values)
    return False


class Rule:
    def __init__(self, raw, source_file):
        self.id = str(raw.get('id', os.path.basename(source_file)))
        self.name = raw.get('name', self.id)
        self.description = raw.get('description', '')
        self.applies_to = raw.get('applies_to')
        self.technique = raw.get('technique', '')
        self.score = raw.get('score', 0)
        self.match = raw.get('match', {})
        self.message_template = raw.get('message', self.name)
        self.enabled = bool(raw.get('enabled', True))
        self.source_file = source_file

    def is_valid(self):
        return (
            self.applies_to in VALID_APPLIES_TO
            and isinstance(self.score, (int, float))
            and isinstance(self.match, dict)
            and ('all' in self.match or 'any' in self.match)
        )

    def matches(self, feature_dict):
        conditions = self.match.get('all') or self.match.get('any') or []
        combinator = all if 'all' in self.match else any
        if not conditions:
            return False

        def _condition_holds(cond):
            field = cond.get('field')
            op = cond.get('op')
            if field is None or op not in VALID_OPS:
                return False
            return _field_matches(feature_dict.get(field), op, cond.get('value'))

        return combinator(_condition_holds(c) for c in conditions)

    def render_message(self, feature_dict):
        try:
            return self.message_template.format(**feature_dict)
        except (KeyError, IndexError):
            return self.message_template


class RuleEngine:
    def __init__(self, rules_dir=DEFAULT_RULES_DIR):
        self.rules_dir = rules_dir
        self.rules = self._load(rules_dir)
        self.hit_counts = {rule.id: 0 for rule in self.rules}

    def _load(self, rules_dir):
        rules = []
        for path in sorted(glob.glob(os.path.join(rules_dir, '*.yml'))) + sorted(glob.glob(os.path.join(rules_dir, '*.yaml'))):
            try:
                with open(path, 'r') as f:
                    raw = yaml.safe_load(f)
                if not isinstance(raw, dict):
                    raise ValueError("rule file must be a YAML mapping")
                rule = Rule(raw, path)
                if not rule.is_valid():
                    raise ValueError(f"invalid rule (bad applies_to/score/match): {rule.id}")
                rules.append(rule)
                logging.info(f"[RULES] Loaded custom rule '{rule.id}' from {os.path.basename(path)}")
            except (yaml.YAMLError, ValueError, OSError) as e:
                logging.warning(f"[RULES] Skipping malformed rule file {path}: {e}")
        return rules

    def _normalize_behavioral(self, event_id, data):
        applies_to = EVENT_ID_TO_APPLIES_TO.get(event_id)
        if applies_to is None:
            return None, None
        field_map = FIELD_MAP[applies_to]
        feature_dict = {}
        for raw_name, norm_name in field_map.items():
            value = data.get(raw_name)
            feature_dict[norm_name] = value.lower() if isinstance(value, str) else value
        return applies_to, feature_dict

    def evaluate_behavioral(self, event_id, data, engine):
        """Evaluate every enabled rule whose applies_to matches this Sysmon
        event type, scoring each hit through the engine's own _add_score()
        so the protected-process floor and decay apply automatically."""
        applies_to, feature_dict = self._normalize_behavioral(event_id, data)
        if applies_to is None:
            return

        pid_field = PID_FIELD[applies_to]
        try:
            pid = int(data.get(pid_field, 0))
        except (TypeError, ValueError):
            return

        dedup_key = data.get('_dedup_key')
        for rule in self.rules:
            if not rule.enabled or rule.applies_to != applies_to:
                continue
            try:
                if rule.matches(feature_dict):
                    scored = engine._score_once(dedup_key, f"rule:{rule.id}", pid, rule.score,
                                                 f"[RULE:{rule.id}] {rule.render_message(feature_dict)}")
                    if scored:
                        self.hit_counts[rule.id] += 1
            except Exception as e:
                logging.warning(f"[RULES] Rule '{rule.id}' failed to evaluate, skipping: {e}")

    def evaluate_static(self, feature_dict):
        """Evaluate every enabled static_pe rule against one sample's
        feature dict. Returns [(rule, message), ...] for the caller
        (static_scanner.py) to route through engine.add_static_score()."""
        hits = []
        for rule in self.rules:
            if not rule.enabled or rule.applies_to != 'static_pe':
                continue
            try:
                if rule.matches(feature_dict):
                    self.hit_counts[rule.id] += 1
                    hits.append((rule, rule.render_message(feature_dict)))
            except Exception as e:
                logging.warning(f"[RULES] Rule '{rule.id}' failed to evaluate, skipping: {e}")
        return hits

    def summary(self):
        """(id, name, technique, score, applies_to, enabled, hit_count) rows
        for the dashboard's Rules tab."""
        return [
            {
                'id': rule.id,
                'name': rule.name,
                'technique': rule.technique,
                'score': rule.score,
                'applies_to': rule.applies_to,
                'enabled': rule.enabled,
                'hit_count': self.hit_counts.get(rule.id, 0),
            }
            for rule in self.rules
        ]
