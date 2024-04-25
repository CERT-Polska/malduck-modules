import logging

from malduck import rc4
from malduck.extractor import Extractor
import json

log = logging.getLogger(__name__)


class Revil(Extractor):
    yara_rules = ("win_revil",)
    family = "revil"

    @Extractor.extractor
    def get_version(self, p, hit):
        last_imm_push = None

        for c in p.disasmv(hit, 0x80):
            if c.mnem == "push" and c.op1.is_imm:
                last_imm_push = c.op1.value

        if last_imm_push and last_imm_push < 0x1000 and last_imm_push > 0x100:
            push_s = hex(last_imm_push)[2:]
            version = f"{push_s[0]}.{push_s[1:]}"
            return {"version": version}

    @Extractor.extractor
    def decrypt_cfg(self, p, hit):
        pushes = []
        registers = {}
        should_return = False
        for c in p.disasmv(hit, 0x60):
            if c.mnem == "push":
                if c.op1.is_reg:
                    pushes.append(registers.get(c.op1.value, "unknown"))
                else:
                    pushes.append(c.op1.value)
            if c.mnem == "mov" and c.op1.is_reg:
                registers[c.op1.value] = c.op2.value
            if c.mnem.startswith("ret") or c.mnem == "stosd":
                if should_return:
                    break
                should_return = True

        if 0x20 not in pushes:
            self.log.warning("Fetched weird params - 0x20 not found")
            return

        # adjust the call parameters
        while pushes[-2] != 0x20 and len(pushes) > 4:
            pushes = pushes[:-1]

        values = pushes[-4:]
        if not all(isinstance(x, int) for x in values):
            self.log.warning("Fetched weird params - not int")
            return

        data_len, data, key_len, key = values
        if data_len > 0x1000:
            data_len = p.uint32v(data_len)
        decrypted = rc4(p.readv(key, key_len), p.readv(data, data_len))

        if not decrypted.endswith(b"\x00"):
            self.log.warning("The decrypted blob doesn't end with a nullbyte")
            return

        try:
            config = json.loads(decrypted.strip(b"\x00").decode("utf-8"))
            return config
        except Exception:
            self.log.exception("Something went wrong while decoding the json config")
