"""
HANDS-ON THREAT classification.

The tag fires on IDENTITY EVIDENCE only (imphash match against a known CS family,
or a custom rule that self-declares Cobalt Strike). Structural patterns (RWX section,
high entropy) deliberately do NOT earn it - they match a dozen families; the tag must
guarantee "this is Cobalt Strike", not "something that smells like a stager".
Single tag string consumed by AlertStore (web_server.py) as an orange-bannered alert.
"""

# Stable contract between detection code and AlertStore; substring-matched so producers
# can append context without breaking the consumer.
HANDS_ON_TAG = '[HANDS-ON THREAT]'
HANDS_ON_LABEL = 'HANDS-ON THREAT'


def is_hands_on_message(message):
    """Substring match: producers may append context around the tag."""
    return bool(message) and HANDS_ON_TAG in message


def _normalize_family(name):
    """Normalize for matching: MalwareBazaar tags CS as CobaltStrike, Cobalt Strike,
    and Cobalt_Strike depending on the reporter."""
    if not isinstance(name, str):
        return ''
    return name.lower().replace(' ', '').replace('_', '').replace('-', '')


# Exact match only - 'cobaltrat' must not earn the banner; a substring check would let it.
COBALT_STRIKE_FAMILY_ALIASES = frozenset({
    'cobaltstrike',        # MalwareBazaar's dominant tag
    'cobalt',              # some reporters shorten it to just this
    'cobaltstrikestager',  # stager-specific tagging
    'cobaltstrikebeacon',  # beacon-stage tagging
})


def is_cobalt_strike_family(family_name):
    """Exact alias match; 'cobaltrat' must not match even though it starts with 'cobalt'."""
    return _normalize_family(family_name) in COBALT_STRIKE_FAMILY_ALIASES


def is_cobalt_strike_rule(rule_id, message=''):
    """True when a custom rule self-declares Cobalt Strike in its id or message.
    Unlike the intel path (exact alias), matches 'cobalt' anywhere in the free-form text."""
    normalized = _normalize_family(f"{rule_id or ''} {message or ''}")
    return 'cobaltstrike' in normalized or 'cobalt' in normalized
