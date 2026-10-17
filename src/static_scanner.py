import os
import json
import hashlib
import logging

import hands_on


# Well-known publishers frequently spoofed via PE version-info resources.
# If a binary claims one of these but ships no Authenticode signature blob
# at all, that's a strong static tell (see rev_analysis1.md - Quasar RAT
# posing as "Windows 11 Setup Utility" / Microsoft Corporation).
SPOOFABLE_VENDORS = ('microsoft', 'google', 'adobe', 'mozilla', 'apple', 'intel', 'nvidia')

# Default location tools/threat_intel_sync.py writes to. Deliberately not
# bundled with any hardcoded hash values here - imphash/family data is
# real-world intel that must come from a verified source (MalwareBazaar's
# API, once configured with an Auth-Key), never guessed from memory. This
# scanner works fine with an empty/missing table; it just won't have any
# known-family matches until the sync script has been run.
KNOWN_IMPHASHES_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'known_imphashes.json')

# Human-readable labels for the string_indicators flags extract_features.py
# can set (see tools/extract_features.py's scan_string_indicators).
STRING_INDICATOR_LABELS = {
    'btc_address_pattern': 'Bitcoin address pattern found (possible crypto-clipper)',
    'eth_address_pattern': 'Ethereum address pattern found (possible crypto-clipper)',
    'discord_webhook': 'Discord webhook URL found (possible C2/exfil channel)',
    'telegram_bot_api': 'Telegram Bot API URL found (possible C2/exfil channel)',
    'pastebin_raw': 'Pastebin raw-paste URL found (possible staged payload fetch)',
    'ip_literal_http_c2': 'Hardcoded IP-literal HTTP(S) URL found (possible C2 without DNS)',
}


def _load_known_imphashes(path):
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        # {"<imphash>": {"family": "...", "sample_count": N, "first_seen": "...", "source": "malwarebazaar"}}
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


class StaticScanner:
    def __init__(self, engine, binaries_path, known_imphashes_path=KNOWN_IMPHASHES_PATH, rule_engine=None):
        self.engine = engine
        self.binaries_path = binaries_path
        self.known_imphashes = _load_known_imphashes(known_imphashes_path)
        # Optional additive YAML rule pack (src/rule_engine.py), evaluated
        # after every hardcoded check below via evaluate_static() - hits
        # are routed through self.engine.add_static_score() same as every
        # hardcoded finding, so nothing about scoring/logging is duplicated.
        self.rule_engine = rule_engine

    def scan(self):
        try:
            with open(self.binaries_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logging.error(f"[STATIC] Failed to read {self.binaries_path}: {e}")
            return

        structural_hashes = {}

        for entry in data:
            filename = entry.get('file_name', 'Unknown')
            file_hash = entry.get('hashes', {}).get('sha256', 'Unknown')
            sections = entry.get('sections', [])
            imports = entry.get('imports', {})

            # Structural feature string for metamorphic clustering
            structural_features = []
            
            # Check Sections
            for sec in sections:
                if sec.get('is_rwx'):
                    self.engine.add_static_score(file_hash, 30, f"{filename}: RWX Section found ({sec.get('name')})", check_id='rwx_section')
                
                if sec.get('entropy', 0) > 7.5:
                    self.engine.add_static_score(file_hash, 30, f"{filename}: High entropy section ({sec.get('name')} - {sec.get('entropy')})", check_id='entropy_section')

                structural_features.append(f"{sec.get('name')}:{sec.get('virtual_size')}")

            # Check Imports
            import_flat = []
            for dll, funcs in imports.items():
                for f in funcs:
                    import_flat.append(f.lower())
            
            if 'virtualallocex' in import_flat and 'writeprocessmemory' in import_flat:
                self.engine.add_static_score(file_hash, 40, f"{filename}: High-risk IAT (Injection pattern)", check_id='injection_iat')
            
            if 'setwindowshookexa' in import_flat and 'httpsendrequesta' in import_flat:
                self.engine.add_static_score(file_hash, 40, f"{filename}: High-risk IAT (Keylogger/Exfil pattern)", check_id='keylogger_iat')

            # LSASS credential-dumping IAT pattern, mirrored from Fibratus's
            # credential_access_lsass_memory_dump_via_minidumpwritedump rule:
            # MiniDumpWriteDump (dbghelp.dll) reachable alongside OpenProcess
            # is the classic procdump/Mimikatz-style LSASS dump primitive.
            if 'minidumpwritedump' in import_flat and 'openprocess' in import_flat:
                self.engine.add_static_score(file_hash, 60, f"{filename}: High-risk IAT (LSASS memory dump primitive - MiniDumpWriteDump+OpenProcess)", check_id='lsass_dump_iat')

            # AMSI bypass pattern: AmsiScanBuffer is the function malware
            # patches in-memory (via VirtualProtect to make its code page
            # writable) to make Windows' AV scan interface always report
            # "clean" - a very common PowerShell/.NET-loader evasion step.
            if 'amsiscanbuffer' in import_flat and 'virtualprotect' in import_flat:
                self.engine.add_static_score(file_hash, 45, f"{filename}: High-risk IAT (AMSI bypass pattern - AmsiScanBuffer+VirtualProtect)", check_id='amsi_bypass_iat')

            # Same technique against ETW (Event Tracing for Windows)
            # instead of AMSI - patching EtwEventWrite blinds exactly the
            # kind of Sysmon/EDR telemetry this project's own behavioral
            # monitor depends on.
            if 'etweventwrite' in import_flat and 'virtualprotect' in import_flat:
                self.engine.add_static_score(file_hash, 45, f"{filename}: High-risk IAT (ETW patch/evasion pattern - EtwEventWrite+VirtualProtect)", check_id='etw_patch_iat')

            # SeDebugPrivilege acquisition: the standard precursor to
            # opening a handle on a protected process like LSASS (Task
            # Manager/legit tools request it too, but combined with the
            # injection/dump patterns above or scored on its own here as a
            # lower-confidence precursor signal it's still worth surfacing).
            if 'adjusttokenprivileges' in import_flat and 'openprocesstoken' in import_flat and \
               any(f in import_flat for f in ('lookupprivilegevaluea', 'lookupprivilegevaluew')):
                self.engine.add_static_score(file_hash, 25, f"{filename}: IAT pattern - token privilege escalation (SeDebugPrivilege-style acquisition)", check_id='sedebugprivilege_iat')

            # Direct/native (Nt*/Zw*) syscalls alongside classic injection
            # APIs is a common EDR-evasion technique: usermode API hooks
            # placed by AV/EDR products sit on the Win32 wrapper functions
            # (VirtualAllocEx, WriteProcessMemory), so malware calls the
            # underlying Nt*/Zw* native APIs directly to bypass those hooks
            # while still achieving the same injection primitive.
            has_native_syscall_import = any(f.startswith('nt') or f.startswith('zw') for f in import_flat)
            if has_native_syscall_import and ('virtualallocex' in import_flat or 'writeprocessmemory' in import_flat):
                self.engine.add_static_score(file_hash, 35, f"{filename}: IAT pattern - direct native (Nt*/Zw*) syscalls alongside injection APIs (possible usermode-hook evasion)", check_id='native_syscall_evasion')

            # Ransomware static pattern: bulk file enumeration plus a
            # crypto API - the static analog of the FileCreate-burst
            # behavioral rule in heuristic_engine.py, catching the same
            # capability before the sample ever runs.
            has_file_enum = any(f in import_flat for f in ('findfirstfilew', 'findnextfilew', 'findfirstfilea'))
            has_crypto_api = any(f in import_flat for f in ('cryptencrypt', 'bcryptencrypt', 'cryptgenkey', 'bcryptgenrandom'))
            if has_file_enum and has_crypto_api:
                self.engine.add_static_score(file_hash, 45, f"{filename}: IAT pattern - bulk file enumeration + crypto API (possible ransomware)", check_id='ransomware_static')

            # String-level indicators from tools/extract_features.py's
            # regex scan (crypto-clipper wallet patterns, webhook/bot C2
            # channels, staged-payload hosting, hardcoded-IP C2).
            string_indicators = entry.get('string_indicators', {}) or {}
            for indicator, present in string_indicators.items():
                if present:
                    label = STRING_INDICATOR_LABELS.get(indicator, indicator)
                    self.engine.add_static_score(file_hash, 25, f"{filename}: {label}", check_id=f'string_indicator:{indicator}')

            # Imphash match against known-family intel (see
            # data/known_imphashes.json, populated by
            # tools/threat_intel_sync.py from MalwareBazaar - empty/absent
            # until that's been run with a valid Auth-Key). Two samples
            # sharing an imphash almost always share compiler-emitted
            # binary lineage even after the bytes are repacked, so this
            # catches variants this project has never seen a sample of.
            #
            # Cobalt Strike is split out as its own classification: a
            # positively-identified Cobalt Strike stager is a HANDS-ON
            # THREAT (an operator's tooling on this host), not a generic
            # family hit, and the tagged log line below is what the
            # dashboard pins to the top of the alert queue with an orange
            # banner (see hands_on.py + web_server.AlertStore). Scoring is
            # identical either way - the classification changes how the
            # finding is SURFACED, never how it is weighed.
            imphash = entry.get('imphash')
            if imphash and imphash in self.known_imphashes:
                known = self.known_imphashes[imphash]
                family = known.get('family', '?')
                intel_note = (f"source: {known.get('source', '?')}, "
                              f"{known.get('sample_count', '?')} samples seen")
                if hands_on.is_cobalt_strike_family(family):
                    logging.warning(
                        f"{hands_on.HANDS_ON_TAG} {filename}: Cobalt Strike stager identified "
                        f"- imphash '{imphash}' matches known family '{family}' ({intel_note})"
                    )
                    self.engine.add_static_score(
                        file_hash, 70,
                        f"{filename}: Cobalt Strike stager - imphash matches known family "
                        f"'{family}' ({intel_note})",
                        check_id='cobalt_strike_stager'
                    )
                else:
                    self.engine.add_static_score(
                        file_hash, 70,
                        f"{filename}: Imphash matches known family '{family}' ({intel_note})",
                        check_id='imphash_family'
                    )

            structural_features.append(str(sorted(import_flat)))

            # Brand-impersonation check: version-info vendor claims a
            # well-known publisher but the file carries no Authenticode
            # signature blob at all (System Informer / Sigcheck-style check,
            # applied here as a pure static-metadata comparison).
            version_info = entry.get('version_info', {}) or {}
            has_signature = entry.get('has_authenticode_signature', False)
            claimed_vendor = (version_info.get('CompanyName') or '').strip().lower()
            if claimed_vendor and not has_signature:
                if any(vendor in claimed_vendor for vendor in SPOOFABLE_VENDORS):
                    self.engine.add_static_score(
                        file_hash, 50,
                        f"{filename}: Unsigned binary claims to be published by '{version_info.get('CompanyName')}' "
                        f"(ProductName='{version_info.get('ProductName', '?')}') - brand impersonation",
                        check_id='brand_impersonation'
                    )

            if self.rule_engine:
                feature_dict = {
                    'filename': filename,
                    'hash': file_hash,
                    'imports_flat': import_flat,
                    'max_entropy': max((sec.get('entropy', 0) for sec in sections), default=0),
                    'has_rwx_section': any(sec.get('is_rwx') for sec in sections),
                    'string_indicators': [k for k, v in (entry.get('string_indicators') or {}).items() if v],
                    'imphash': entry.get('imphash'),
                    'company_name': version_info.get('CompanyName'),
                    'product_name': version_info.get('ProductName'),
                    'has_signature': has_signature,
                }
                for rule, message in self.rule_engine.evaluate_static(feature_dict):
                    self.engine.add_static_score(file_hash, rule.score, f"{filename}: [RULE:{rule.id}] {message}", check_id=f'rule:{rule.id}')
                    # A custom rule that self-declares Cobalt Strike earns
                    # the HANDS-ON THREAT classification by operator
                    # declaration - the rule author already made the
                    # family-attribution call this tag requires. Same
                    # tagged-line mechanism as the imphash path above, so
                    # the dashboard pins and banners it identically.
                    if hands_on.is_cobalt_strike_rule(rule.id, message):
                        logging.warning(
                            f"{hands_on.HANDS_ON_TAG} {filename}: Cobalt Strike stager identified "
                            f"by custom rule '{rule.id}' - {message}"
                        )

            # Calculate Structural Hash
            struct_str = "|".join(structural_features)
            struct_hash = hashlib.sha256(struct_str.encode()).hexdigest()
            
            if struct_hash in structural_hashes:
                other_file = structural_hashes[struct_hash]
                if other_file['sha256'] != file_hash:
                    # add_static_score() already no-ops for an allowlisted
                    # file_hash, but that alone leaves this WARNING log line
                    # firing regardless - a known-good file would still show
                    # up as a "Metamorphic Clone Detected!" alert even
                    # though its score is correctly suppressed. Guard the
                    # log line itself too.
                    if not self.engine.is_allowlisted(file_hash):
                        logging.warning(f"[STATIC] Metamorphic Clone Detected! {filename} and {other_file['filename']} share exact structural hash but different SHA-256.")
                    self.engine.add_static_score(file_hash, 50, "Metamorphic Clone", check_id='metamorphic_clone')
            else:
                structural_hashes[struct_hash] = {
                    'filename': filename,
                    'sha256': file_hash
                }
