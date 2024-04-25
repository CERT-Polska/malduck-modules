from malduck import Extractor, procmempe
from malduck import chunks, xor, UInt32
import string


def derive_key(data: bytes) -> bytes:
    k = list(data)
    for i in range(15, -1, -1):
        k[i] = (k[i] + 1) % 256
        if k[i] != 0:
            break
    return bytes(k)


def decrypt_data(data: bytes) -> bytes:
    key_1 = data[:16]
    key_2 = data[16:32]

    key_1, key_2 = key_2, key_1
    data = data[32:]

    out = []
    for chunk in chunks(data, 16):
        key = key_2
        key = xor(key, key_1)
        a, b, c, d = (UInt32 * 4).unpack(key)
        for _ in range(16):
            a += b
            b = a ^ ((32 * b) | (b >> 27))
            c += d
            d = c ^ ((d << 8) | (d >> 24))
            c += b
            a = d + ((a << 16) | (a >> 16))
            d = a ^ ((d << 13) | (d >> 19))
            b = c ^ ((b << 7) | (b >> 25))
            c = (c << 16) | (c >> 16)
        key = a.pack() + b.pack() + c.pack() + d.pack()
        key = xor(key, key_1)
        out.append(xor(key, chunk))
        key_2 = derive_key(key_2)
    return b"".join(out)


class GraphicalProton(Extractor):
    family = "graphical_proton"
    yara_rules = ("win_graphical_proton",)

    @Extractor.needs_pe
    @Extractor.extractor
    def op_decrypt_config(self, p: procmempe, hit: int):
        data_chunks = []

        addr = None
        for i in p.disasmv(hit, count=128, x64=True):
            if i.mnem == "lea":
                addr = i.op2.value
            elif i.mnem == "mov" and i.op2.is_imm and addr:
                data = p.readv(i.addr + addr, i.op2.value)
                if data:
                    data_chunks.append(data)
                addr = None

        strings = [decrypt_data(x) for x in data_chunks]
        strings = list(
            filter(lambda x: all(q in string.printable.encode() for q in x), strings)
        )
        strings = [x.decode() for x in strings]

        if len(strings) == 6:
            config = {
                "graph-client-id": strings[0],
                "project-name": strings[1],
                "graph-token": strings[2],
                "dropbox-client-secret": strings[3],
                "dropbox-client-id": strings[4],
                "dropbox-token": strings[5],
            }
            return config
