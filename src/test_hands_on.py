"""
Self-check for hands_on.py - the HANDS-ON THREAT classification authority.
The whole point of this module is precision: the banner must fire on
Cobalt Strike identity evidence and NEVER on a near-miss or a generic
shellcode-shaped finding. Run: python test_hands_on.py
"""

import hands_on as ho


def test_tag_detection_is_substring_based():
    # Producers wrap the tag with arbitrary context; the consumer must
    # recognize it wherever it sits in the message.
    assert ho.is_hands_on_message(
        f"{ho.HANDS_ON_TAG} evil.exe: Cobalt Strike stager identified - imphash deadbeef")
    assert ho.is_hands_on_message(
        "prefix noise [HANDS-ON THREAT] suffix noise")
    assert not ho.is_hands_on_message("ordinary finding, nothing attached")
    assert not ho.is_hands_on_message("")
    assert not ho.is_hands_on_message(None)
    # a message that merely TALKS about hands-on threats is not tagged
    assert not ho.is_hands_on_message(
        "analyst wrote a note mentioning HANDS-ON THREAT without the tag format")


def test_tag_constant_is_a_stable_contract():
    # The tag is a producer/consumer contract shared by static_scanner and
    # AlertStore - if it ever changes, it must change deliberately.
    assert ho.HANDS_ON_TAG == '[HANDS-ON THREAT]'
    assert ho.HANDS_ON_LABEL == 'HANDS-ON THREAT'


def test_cobalt_strike_family_spelling_variants_match():
    # MalwareBazaar reporters spell the family inconsistently; all of
    # these are the same family and all must match.
    for family in ('CobaltStrike', 'cobaltstrike', 'Cobalt Strike',
                   'Cobalt_Strike', 'Cobalt-Strike', 'Cobalt',
                   'CobaltStrikeStager', 'CobaltStrikeBeacon'):
        assert ho.is_cobalt_strike_family(family), f"'{family}' must match"


def test_near_miss_and_unrelated_families_rejected():
    # The banner must mean Cobalt Strike and nothing else: near-misses
    # that merely START with 'cobalt' as raw text are the exact trap the
    # exact-alias matcher exists to avoid.
    for family in ('Cobaltrat', 'CobaltCat', 'Cobint', 'AsyncRAT',
                   'QuasarRAT', '', None, 12345):
        assert not ho.is_cobalt_strike_family(family), f"'{family}' must NOT match"


def test_cobalt_strike_rule_detection():
    # Rule ids are free-form; the family name appearing anywhere in the
    # id (or the hit message) is a declaration of attribution. Note 'cs_'
    # as an abbreviation deliberately does NOT count - 'cs' alone is
    # ambiguous (CountrySpecifier? CheatSheet?) and the tag must never
    # fire on a guess.
    assert ho.is_cobalt_strike_rule('cobalt_strike_stager_load')
    assert ho.is_cobalt_strike_rule('cobalt-strike-download-cradle')
    assert ho.is_cobalt_strike_rule('generic_loader', message='matches Cobalt Strike stager behavior')
    assert not ho.is_cobalt_strike_rule('cs_beacon_download_cradle')  # abbreviation alone is not identity
    assert not ho.is_cobalt_strike_rule('generic_loader_load')
    assert not ho.is_cobalt_strike_rule('', message='')
    assert not ho.is_cobalt_strike_rule(None)


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
