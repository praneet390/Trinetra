"""
HANDS-ON THREAT classification.

"Cobalt Strike stager" detections are a fundamentally different class of
finding from generic shellcode hits: a shellcode section or a high-entropy
PE segment is *suspicious code*, while a positively-identified Cobalt
Strike stager means an operator's tooling is (or is about to be) executing
on this host - the "hands-on-keyboard" signature of a targeted intrusion.
This module is the single authority for deciding which findings earn that
classification, so every consumer (the static scanner that emits the
tagged log line, the web dashboard's AlertStore that pins and banners it)
shares one definition instead of four drifting copies of the same test.

How a finding becomes HANDS-ON THREAT
-------------------------------------
1. IDENTITY EVIDENCE ONLY. The tag is applied when something positively
   identifies the Cobalt Strike tool family - today that is:
   - an imphash match against a known family whose name is Cobalt Strike
     (data/known_imphashes.json, populated from MalwareBazaar by
     tools/threat_intel_sync.py), or
   - a custom YAML rule whose id/name declares Cobalt Strike (the rule
     author has made exactly the family-attribution call this module
     exists to recognize).
   Structural patterns alone (a download-execute IAT trio, an RWX section,
   entropy) deliberately DO NOT earn the tag: they are consistent with a
   dozen loader families and half the legit installer ecosystem. Tagging
   them would dilute the one thing the classification must guarantee -
   when the banner shows, an analyst knows it is Cobalt Strike, not
   "something that smells like a stager".

2. ONE TAG, ONE PLACE. The detection emits its normal scored finding
   (so scoring, allowlisting and dedup are untouched) plus a single
   `[HANDS-ON THREAT]`-prefixed warning log line. The dashboard's
   AlertStore turns any log message carrying that tag into a pinned,
   orange-bannered alert - see web_server.AlertStore and the
   `hands_on`/`classification` fields it attaches.

The tag string itself is a stable contract between producer (detection
code) and consumer (AlertStore), deliberately checked by substring so a
tagged line stays tagged no matter how much context surrounds it.
"""

# The stable producer/consumer contract. AlertStore (web_server.py)
# recognizes this exact substring and promotes such alerts to the pinned,
# orange-bannered HANDS-ON THREAT class. Kept here rather than duplicated
# in both files so the two ends can never drift apart.
HANDS_ON_TAG = '[HANDS-ON THREAT]'

# The human-facing classification label rendered on the banner.
HANDS_ON_LABEL = 'HANDS-ON THREAT'


def is_hands_on_message(message):
    """True when a log/alert message carries the HANDS-ON THREAT tag.

    Substring match on purpose: producers may append arbitrary context
    (filename, imphash, family source) around the tag, and the consumer
    must not have to keep its prefix/shape in sync with every producer.
    """
    return bool(message) and HANDS_ON_TAG in message


def _normalize_family(name):
    """Lowercase a family label and strip the separators real-world intel
    feeds spell it with - MalwareBazaar alone tags Cobalt Strike as
    'CobaltStrike', 'Cobalt Strike', 'Cobalt_Strike' depending on the
    reporter, and the matcher below must treat all of them as one family."""
    if not isinstance(name, str):
        return ''
    return name.lower().replace(' ', '').replace('_', '').replace('-', '')


# Normalized family labels that positively identify Cobalt Strike. The
# match is EXACT against this alias set (never a substring/startswith
# check): a near-miss family like 'Cobaltrat' must not earn the banner,
# and a loose text match would let it. Add new intel aliases here as they
# appear in feeds - do not loosen the matching.
COBALT_STRIKE_FAMILY_ALIASES = frozenset({
    'cobaltstrike',        # MalwareBazaar's dominant tag
    'cobalt',              # some reporters shorten it to just this
    'cobaltstrikestager',  # stager-specific tagging
    'cobaltstrikebeacon',  # beacon-stage tagging
})


def is_cobalt_strike_family(family_name):
    """True when a threat-intel family label identifies Cobalt Strike.

    Deliberately narrow (exact alias match on the normalized label): this
    gates the HANDS-ON THREAT banner, so a near-miss family like
    'Cobaltrat' must NOT match even though its name starts with 'cobalt'.
    If a new alias for the family shows up in intel, add it to
    COBALT_STRIKE_FAMILY_ALIASES - do not loosen the matching."""
    return _normalize_family(family_name) in COBALT_STRIKE_FAMILY_ALIASES


def is_cobalt_strike_rule(rule_id, message=''):
    """True when a custom YAML rule self-declares Cobalt Strike.

    Rule authors who write a Cobalt Strike rule have already made the
    family-attribution call; their rule id (or hit message) naming the
    family is identity evidence by declaration. Unlike the intel path
    above - which matches one family *label* exactly - this matches the
    family name appearing anywhere in the free-form rule id or hit
    message ('cs_stager_beacon', 'cobalt-strike-download-cradle')."""
    normalized = _normalize_family(f"{rule_id or ''} {message or ''}")
    return 'cobaltstrike' in normalized or 'cobalt' in normalized
