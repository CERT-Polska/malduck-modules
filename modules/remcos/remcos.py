import logging
import re
import string
from typing import Any, Dict, List

from malduck import procmem, rc4
from malduck.extractor import Extractor

log = logging.getLogger(__name__)


def pretty_print_config(config: List[bytes]) -> Dict[str, Any]:
    content = "\n".join(repr(x)[1:] for x in config)
    return {
        "in-blob": {"blob_name": "raw_cfg", "blob_type": "raw_cfg", "content": content}
    }


def brute_key(config: bytes) -> bytes:
    for match in re.findall(b"\x00(.*?)\x00", config):
        if config.count(match) in range(50, 60) and match not in (b".", b":"):
            return match


class Remcos(Extractor):
    yara_rules = ("win_remcos", "win_remcos_auto")
    family = "remcos"

    @Extractor.needs_pe
    @Extractor.final
    def get_config(self, p: procmem) -> None:
        data = p.pe.resource("SETTINGS")

        if not data:
            log.error("SETTINGS resource not found or empty")
            return None

        log.info("got encrypted section")

        key_len = data[0]
        key = data[1:][:key_len]
        encrypted = data[1 + key_len :]
        decrypted = rc4(key, encrypted)
        print(decrypted)
        split_key = brute_key(decrypted)

        if split_key is None:
            log.error("couldn't find split_key")
            return None

        log.info("got split_key")

        config_list = decrypted.split(split_key)
        C2_NEEDLES = [b"|", b"\xff\xff\xff\xff", b"\x1e"]

        c2s = [config_list[0].strip(b"\n")]
        for needle in C2_NEEDLES:
            if len(c2s) == 1 and c2s[0].count(needle) > 0:
                c2s = c2s[0].strip(needle).split(needle)

        log.info("found {num} c2s".format(num=len(c2s)))

        config = {
            "family": "remcos",
            "raw_cfg": pretty_print_config(config_list),
            "c2": [],
        }
        for c2 in c2s:
            host = b":".join(c2.split(b":")[:2])
            password = b":".join(c2.split(b":")[2:])

            c2_conf = {
                "host": host,
            }

            if all(x in string.printable.encode() for x in password):
                c2_conf["password"] = password

            config["c2"].append(c2_conf)

        self.push_config(config)
        return None
