import logging
import pprint
from typing import List, cast, Any, Dict, TypeAlias
from urllib.parse import urlparse, urlunparse

import malduck
from libcsce.error import ConfigNotFoundError, MissingDataSectionError
from libcsce.parser import CobaltStrikeConfigParser
from malduck.extractor import Extractor
from malduck.procmem import ProcessMemoryPE
from malduck.yara import YaraRuleMatch

logger = logging.getLogger(__name__)

Config: TypeAlias = Dict[str, Any]

def get_rule_metadata(match: YaraRuleMatch) -> Config:
    """
    Parses metadata from YARA rule into dictionary under `rule` and
    top-level keys suitable for inclusion under `threat.software` ECS schema.
    At a minumum, it will contain the name of the rule.
    """
    rule_info: Config = {}
    software_info: Config = {}

    rule_info["name"] = match.name

    if match.meta:
        _meta = match.meta
        if _meta.get("author", None):
            rule_info["author"] = _meta.get("author")
        if _meta.get("id", None):
            rule_info["id"] = _meta["id"]
        if _meta.get("category_type", None):
            rule_info["category"] = _meta["category_type"]
        elif _meta.get("category", None):
            rule_info["category"] = _meta["category"]
        if _meta.get("description", None):
            rule_info["description"] = _meta["description"]
        if _meta.get("license", None):
            rule_info["license"] = _meta["license"]
        if _meta.get("reference", None):
            rule_info["reference"] = _meta["reference"]
        if _meta.get("ruleset", None):
            rule_info["ruleset"] = _meta["ruleset"]
        if _meta.get("version", None):
            rule_info["version"] = _meta["version"]
        elif _meta.get("rev", None):
            rule_info["version"] = _meta["rev"]
        if _meta.get("tlp", None):
            rule_info["tlp"] = _meta["tlp"]

        if _meta.get("threat_name", None):
            software_info["name"] = _meta["threat_name"]
        if _meta.get("os", None):
            software_info["platforms"] = _meta["os"].split(",")
        if _meta.get("arch", None):
            software_info["architectures"] = _meta["arch"].split(",")
        if _meta.get("reference", None):
            software_info["reference"] = _meta["reference"]

    software_info["rule"] = rule_info

    return software_info

class CobaltStrike(Extractor):
    family: str = "cobalt_strike"
    yara_rules = ("cobalt_strike",)
    overrides = []
    info: Config = {}

    @Extractor.needs_pe
    @Extractor.rule
    def cobalt_strike(self, p: ProcessMemoryPE, match: YaraRuleMatch) -> Config | bool:

        """
        :param p: ProcessMemory object that contains matched file/dump representation
        :return: config
        """

        _info: Config = get_rule_metadata(match)

        _b = p.store()

        _beacon = CobaltStrikeConfigParser(_b, 4)
        try:
            _parsed_config: Config = cast(Config, _beacon.parse_config())
        except ConfigNotFoundError:
            logger.info("Sample did not contain a CobaltStrike config")
            return {}
        except MissingDataSectionError:
            logger.info("CobaltStrike sample did not contain a .data section")
            return {}

        _proc_inject = dict(_parsed_config["process-inject"])
        if "stub" in _proc_inject:
            _proc_inject["stub"] = cast(bytes, _proc_inject["stub"]).hex()

        beacons: List[str] = _parsed_config["beacontype"]

        # Populate general-purpose config first
        _config = {
            "family": self.family,
            "urls": [],
            self.family: {
                "beacon_type": beacons,
                "sleep_time": _parsed_config["sleeptime"],
                "jitter": _parsed_config["jitter"],
                "max_get_size": _parsed_config["maxgetsize"],
                "spawn_to": cast(bytes, _parsed_config["spawnto"]).hex(),
                "license_id": _parsed_config["license_id"],
                "cfg_caution": _parsed_config["cfg_caution"],
                "kill_date": _parsed_config["kill_date"],
                "crypto_scheme": _parsed_config["crypto_scheme"],
                "post_exploitation": _parsed_config["post-ex"],
                "stage": _parsed_config["stage"],
                "proxy": _parsed_config["proxy"],
                "process_inject": _proc_inject,
                # HTTP/S and Hybrid Beacon Settings
                "http": {
                    "server": {
                        "hostname": _parsed_config["server"]["hostname"],
                        "port": _parsed_config["server"]["port"],
                        "public_key": _parsed_config["server"]["publickey"].hex(),
                    },
                    "get": _parsed_config["http-get"],
                    "post": _parsed_config["http-post"],
                    "post_chunk": _parsed_config["http_post_chunk"],
                    "host_header": _parsed_config["host_header"],
                    "user_agent": _parsed_config["useragent_header"],
                    "uses_cookies": _parsed_config["uses_cookies"],
                },
                # DNS Beacon settings
                "dns": {
                    "dns_idle": _parsed_config["dns-beacon"]["dns_idle"],
                    "dns_sleep": _parsed_config["dns-beacon"]["dns_sleep"],
                    "max_dns": _parsed_config["dns-beacon"]["maxdns"],
                    "beacon": _parsed_config["dns-beacon"]["beacon"],
                    "get_A": _parsed_config["dns-beacon"]["get_A"],
                    "get_AAAA": _parsed_config["dns-beacon"]["get_AAAA"],
                    "get_TXT": _parsed_config["dns-beacon"]["get_TXT"],
                    "put_metadata": _parsed_config["dns-beacon"]["put_metadata"],
                    "put_output": _parsed_config["dns-beacon"]["put_output"],
                },
                # SMB Beacon settings
                "smb": {
                    "frame_header": cast(
                        bytes, _parsed_config["smb_frame_header"]
                    ).hex()
                    if _parsed_config["smb_frame_header"]
                    else None,
                    "pipe_name": _parsed_config["pipename"],
                },
                # SSH Client settings
                "ssh": {
                    "hostname": _parsed_config["ssh"]["hostname"],
                    "port": _parsed_config["ssh"]["port"],
                    "username": _parsed_config["ssh"]["username"],
                    "password": _parsed_config["ssh"]["password"],
                    "privatekey": _parsed_config["ssh"]["hostname"],
                },
                # TCP Options
                "tcp_frame_header": malduck.enhex(
                    _parsed_config["tcp_frame_header"]
                ).decode("utf-8"),
            },
        }

        schemes = {"http", "https"} & set(beacons)
        if schemes:
            for scheme in schemes:
                netloc = "%s:%s" % (
                    _parsed_config[self.family]["server"]["hostname"],
                    _parsed_config[self.family]["server"]["port"],
                )

                # (scheme, network location, path, query, fragment).
                _config["urls"] += urlunparse(
                    (
                        scheme.lower(),
                        netloc,
                        _config[self.family]["http"]["get"]["uri"],
                        "",
                        "",
                        "",
                    )
                )
                _config["urls"] += urlunparse(
                    (
                        scheme.lower(),
                        netloc,
                        _config[self.family]["http"]["post"]["uri"],
                        "",
                        "",
                        "",
                    )
                )

            # This can be processed by the useragent ingest processor
            _config["user_agent"] = {"original": _parsed_config["useragent_header"]}

        smb_hostname = None
        if "smb" in beacons:
            _parts = urlparse(
                _parsed_config[self.family]["smb"]["pipe_name"].replace("\\", "/")
            )._asdict()
            _parts["scheme"] = "smb"
            _config["urls"] = urlunparse(_parts.values())

            # Parse SMB hostname if not '.'
            smb_hostname = _parts["netloc"].split(":")[0]
            if smb_hostname == ".":
                smb_hostname = None

        _config["hostname"] = []
        if _parsed_config["server"]["hostname"]:
            _config["hostname"].append(_parsed_config["server"]["hostname"])
        if _parsed_config["ssh"]["hostname"]:
            _config["hostname"].append(_parsed_config["ssh"]["hostname"])
        if smb_hostname:
            _config["hostname"].append(smb_hostname)

        # Remove the URLs field if it's empty
        if not _config["urls"]:
            del _config["urls"]

        return _config | _info
