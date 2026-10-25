"""
Self-check for kernel_sensor.py's pure parsing/dispatch/drop-detection
logic. No real driver/device handle - parse_event is tested against
synthetic bytes built with the exact same struct format the module uses,
the same way test_etw_monitor.py exercises _on_etw_event with synthetic
(event_id, event_dict) tuples instead of a real ETW session.
Run: python test_kernel_sensor.py
"""

import struct

import kernel_sensor as ks


def _build_event_bytes(seq=1, event_type=ks.EVENT_TYPE_PROCESS_CREATE, ppid_spoof=0,
                        pid=100, field2=1, field3=1, field4=0,
                        truncated=0, image_name="evil.exe"):
    name_bytes = image_name.encode('utf-16-le')
    name_bytes = name_bytes[:ks.IMAGE_NAME_MAX_CHARS * 2 - 2]  # leave room for the NUL
    padded = name_bytes.ljust(ks.IMAGE_NAME_MAX_CHARS * 2, b'\x00')
    return struct.pack(ks._EVENT_FORMAT, seq, event_type, ppid_spoof, pid,
                        field2, field3, field4, truncated, 0, padded)


def test_ctl_code_matches_the_wdk_macro():
    # CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x800, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
    # = (0x22 << 16) | (0 << 14) | (0x800 << 2) | 0 = 0x220000 | 0x2000 = 0x222000
    assert ks.IOCTL_GET_EVENT == 0x222000
    assert ks.IOCTL_REGISTER_SELF == 0x222004
    assert ks.IOCTL_UNREGISTER_SELF == 0x222008


def test_event_size_matches_sensor_c_struct_layout():
    # ULONG64 x5 (40) + ULONG x4 (16) + WCHAR[260] (520) = 576, zero padding
    assert ks.EVENT_SIZE == 576


def test_parse_event_round_trips_basic_fields():
    raw = _build_event_bytes(seq=42, pid=1234, field2=1, field3=1, image_name="cmd.exe")
    event = ks.parse_event(raw)
    assert event['sequence_number'] == 42
    assert event['event_type'] == ks.EVENT_TYPE_PROCESS_CREATE
    assert event['pid'] == 1234
    assert event['image_name'] == "cmd.exe"
    assert event['image_name_truncated'] is False
    assert event['ppid_spoof_detected'] is False


def test_parse_event_decodes_ppid_spoof_flag():
    raw = _build_event_bytes(ppid_spoof=1, field2=999, field3=1234)
    event = ks.parse_event(raw)
    assert event['ppid_spoof_detected'] is True
    assert event['field2'] == 999
    assert event['field3'] == 1234


def test_parse_event_handles_empty_image_name():
    raw = _build_event_bytes(image_name="")
    event = ks.parse_event(raw)
    assert event['image_name'] == ""


def test_parse_event_decodes_truncated_flag():
    raw = _build_event_bytes(truncated=1)
    assert ks.parse_event(raw)['image_name_truncated'] is True


def test_parse_event_rejects_short_buffer():
    try:
        ks.parse_event(b'\x00' * 10)
        assert False, "expected struct.error on a too-short buffer"
    except struct.error:
        pass


# ---- _dispatch_event: routes by event_type -----------------------------

class _FakeCorrelator:
    def __init__(self):
        self.kernel_calls = []

    def submit_kernel(self, pid, claimed_parent_pid, real_creator_pid, image_name, ppid_spoof_detected):
        self.kernel_calls.append((pid, claimed_parent_pid, real_creator_pid, image_name, ppid_spoof_detected))


class _FakeEngine:
    def __init__(self):
        self.lsass_calls = []
        self.driver_load_calls = []

    def evaluate_kernel_lsass_access(self, requestor_pid, target_pid, desired_access):
        self.lsass_calls.append((requestor_pid, target_pid, desired_access))

    def evaluate_kernel_driver_load(self, pid, image_name, image_base):
        self.driver_load_calls.append((pid, image_name, image_base))


def test_dispatch_routes_process_create_to_correlator():
    correlator, engine = _FakeCorrelator(), _FakeEngine()
    event = ks.parse_event(_build_event_bytes(
        event_type=ks.EVENT_TYPE_PROCESS_CREATE, pid=50, field2=10, field3=20,
        ppid_spoof=1, image_name="evil.exe",
    ))
    ks._dispatch_event(event, correlator, engine)
    assert correlator.kernel_calls == [(50, 10, 20, "evil.exe", True)]
    assert engine.lsass_calls == [] and engine.driver_load_calls == []


def test_dispatch_routes_lsass_access_to_engine():
    correlator, engine = _FakeCorrelator(), _FakeEngine()
    event = ks.parse_event(_build_event_bytes(
        event_type=ks.EVENT_TYPE_LSASS_ACCESS, pid=792, field2=1337, field4=0x10,
    ))
    ks._dispatch_event(event, correlator, engine)
    assert engine.lsass_calls == [(1337, 792, 0x10)]
    assert correlator.kernel_calls == [] and engine.driver_load_calls == []


def test_dispatch_routes_driver_load_to_engine():
    correlator, engine = _FakeCorrelator(), _FakeEngine()
    event = ks.parse_event(_build_event_bytes(
        event_type=ks.EVENT_TYPE_DRIVER_LOAD, pid=4, field4=0xFFFFF80000000000, image_name="evil.sys",
    ))
    ks._dispatch_event(event, correlator, engine)
    assert engine.driver_load_calls == [(4, "evil.sys", 0xFFFFF80000000000)]
    assert correlator.kernel_calls == [] and engine.lsass_calls == []


def test_dispatch_ignores_unknown_event_type_without_raising():
    correlator, engine = _FakeCorrelator(), _FakeEngine()
    event = ks.parse_event(_build_event_bytes(event_type=999))
    ks._dispatch_event(event, correlator, engine)  # must not raise
    assert correlator.kernel_calls == [] and engine.lsass_calls == [] and engine.driver_load_calls == []


# ---- _record_sequence_gap: drop detection via sequence-number gaps -----

def test_sequence_gap_detects_missing_events():
    drops = []
    holder = [5]
    event = ks.parse_event(_build_event_bytes(seq=8))  # 6,7 missing
    ks._record_sequence_gap(event, holder, on_drop=lambda: drops.append(1))
    assert len(drops) == 2
    assert holder[0] == 8


def test_sequence_gap_no_drop_for_consecutive_events():
    drops = []
    holder = [5]
    event = ks.parse_event(_build_event_bytes(seq=6))
    ks._record_sequence_gap(event, holder, on_drop=lambda: drops.append(1))
    assert drops == []
    assert holder[0] == 6


def test_sequence_gap_first_event_never_counts_as_a_drop():
    drops = []
    holder = [None]
    event = ks.parse_event(_build_event_bytes(seq=500))
    ks._record_sequence_gap(event, holder, on_drop=lambda: drops.append(1))
    assert drops == [], "no prior sequence number to compare against yet - nothing was lost"
    assert holder[0] == 500


def test_sequence_gap_handles_missing_on_drop_callback():
    holder = [1]
    event = ks.parse_event(_build_event_bytes(seq=5))
    ks._record_sequence_gap(event, holder, on_drop=None)  # must not raise
    assert holder[0] == 5


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"OK ({len(tests)} checks)")
