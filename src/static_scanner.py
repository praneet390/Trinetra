import os
import json
import hashlib
import logging

import hands_on


# Well-known publishers frequently spoofed via PE version-info resources.
SPOOFABLE_VENDORS = ('microsoft', 'google', 'adobe', 'mozilla', 'apple', 'intel', 'nvidia')

# tools/threat_intel_sync.py writes here. Empty/absent until that script has
# been run with a MalwareBazaar Auth-Key; scanner works fine without it.
KNOWN_IMPHASHES_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'known_imphashes.json')

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
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


class StaticScanner:
    def __init__(self, engine, binaries_path, known_imphashes_path=KNOWN_IMPHASHES_PATH, rule_engine=None):
        self.engine = engine
        self.binaries_path = binaries_path
        self.known_imphashes = _load_known_imphashes(known_imphashes_path)
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

            structural_features = []

            for sec in sections:
                if sec.get('is_rwx'):
                    self.engine.add_static_score(file_hash, 30, f"{filename}: RWX Section found ({sec.get('name')})", check_id='rwx_section')
                
                if sec.get('entropy', 0) > 7.5:
                    self.engine.add_static_score(file_hash, 30, f"{filename}: High entropy section ({sec.get('name')} - {sec.get('entropy')})", check_id='entropy_section')

                structural_features.append(f"{sec.get('name')}:{sec.get('virtual_size')}")

            import_flat = []
            for dll, funcs in imports.items():
                for f in funcs:
                    import_flat.append(f.lower())
            
            if 'virtualallocex' in import_flat and 'writeprocessmemory' in import_flat:
                self.engine.add_static_score(file_hash, 40, f"{filename}: High-risk IAT (Injection pattern)", check_id='injection_iat')
            
            if 'setwindowshookexa' in import_flat and 'httpsendrequesta' in import_flat:
                self.engine.add_static_score(file_hash, 40, f"{filename}: High-risk IAT (Keylogger/Exfil pattern)", check_id='keylogger_iat')

            # MiniDumpWriteDump + OpenProcess is the classic procdump/Mimikatz LSASS dump primitive.
            if 'minidumpwritedump' in import_flat and 'openprocess' in import_flat:
                self.engine.add_static_score(file_hash, 60, f"{filename}: High-risk IAT (LSASS memory dump primitive - MiniDumpWriteDump+OpenProcess)", check_id='lsass_dump_iat')

            # AmsiScanBuffer + VirtualProtect: malware patches AMSI in-memory to always report clean.
            if 'amsiscanbuffer' in import_flat and 'virtualprotect' in import_flat:
                self.engine.add_static_score(file_hash, 45, f"{filename}: High-risk IAT (AMSI bypass pattern - AmsiScanBuffer+VirtualProtect)", check_id='amsi_bypass_iat')

            # EtwEventWrite + VirtualProtect: same patch technique to blind EDR/Sysmon telemetry.
            if 'etweventwrite' in import_flat and 'virtualprotect' in import_flat:
                self.engine.add_static_score(file_hash, 45, f"{filename}: High-risk IAT (ETW patch/evasion pattern - EtwEventWrite+VirtualProtect)", check_id='etw_patch_iat')

            # AdjustTokenPrivileges + LookupPrivilegeValue: SeDebugPrivilege acquisition pattern.
            if 'adjusttokenprivileges' in import_flat and 'openprocesstoken' in import_flat and \
               any(f in import_flat for f in ('lookupprivilegevaluea', 'lookupprivilegevaluew')):
                self.engine.add_static_score(file_hash, 25, f"{filename}: IAT pattern - token privilege escalation (SeDebugPrivilege-style acquisition)", check_id='sedebugprivilege_iat')

            # Nt*/Zw* alongside injection APIs: direct syscalls bypass usermode API hooks placed by EDR.
            has_native_syscall_import = any(f.startswith('nt') or f.startswith('zw') for f in import_flat)
            if has_native_syscall_import and ('virtualallocex' in import_flat or 'writeprocessmemory' in import_flat):
                self.engine.add_static_score(file_hash, 35, f"{filename}: IAT pattern - direct native (Nt*/Zw*) syscalls alongside injection APIs (possible usermode-hook evasion)", check_id='native_syscall_evasion')

            has_file_enum = any(f in import_flat for f in ('findfirstfilew', 'findnextfilew', 'findfirstfilea'))
            has_crypto_api = any(f in import_flat for f in ('cryptencrypt', 'bcryptencrypt', 'cryptgenkey', 'bcryptgenrandom'))
            if has_file_enum and has_crypto_api:
                self.engine.add_static_score(file_hash, 45, f"{filename}: IAT pattern - bulk file enumeration + crypto API (possible ransomware)", check_id='ransomware_static')

            string_indicators = entry.get('string_indicators', {}) or {}
            for indicator, present in string_indicators.items():
                if present:
                    label = STRING_INDICATOR_LABELS.get(indicator, indicator)
                    self.engine.add_static_score(file_hash, 25, f"{filename}: {label}", check_id=f'string_indicator:{indicator}')

            # Cobalt Strike split from generic imphash hits: a confirmed stager is a HANDS-ON THREAT,
            # which the dashboard pins at the top; scoring is identical, classification changes surfacing.
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
                    if hands_on.is_cobalt_strike_rule(rule.id, message):
                        logging.warning(
                            f"{hands_on.HANDS_ON_TAG} {filename}: Cobalt Strike stager identified "
                            f"by custom rule '{rule.id}' - {message}"
                        )

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
