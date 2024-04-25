rule win_revil
{
    meta:
        author = "CERT Polska"
        date = "2020-01-21"
    strings:
        $set_lang = { C7 45 [1] 19 04 00 00 C7 45 [1] 22 04 00 00 C7 45 [1] 23 04 00 00 C7 45 [1] 28 04 00 00 C7 45 [1] 2B 04 00 00 C7 45 [1] 2C 04 00 00 C7 45 [1] 37 04 00 00 C7 45 [1] 3F 04 00 00 }
        $hash_fun = { 2B [0-10] 69 [1] 0F 01 00 00 4? 0F [2] 03 [1] 8A [1] 84 }
        $salsa_keystream = "expand 32-byte kexpand 16-byte"

        // 6A 00                                   push    0
        // E8 BF 3D 00 00                          call    crc32
        // .... 
        // 56                                      push    esi
        // FF 35 24 E0 41 00                       push    ds:dword_41E024
        // 57                                      push    edi
        // 6A 20                                   push    20h ; ' '
        // 68 00 E0 41 00                          push    offset unk_41E000
        // E8 41 44 00 00                          call    rc4
        $decrypt_cfg = { 5? [5-20] 6a 00 e8 [0-50] 5? ff [5] 5? 6a 20 68 [4] e8 }

        // 68 3A 01 00 00                          push    13Ah
        // ...
        // FF 35 AC 35 41 00                       push    dword_4135AC    ; _DWORD
        // FF 35 4C 35 41 00                       push    dword_41354C    ; _DWORD
        // FF 35 48 35 41 00                       push    dword_413548    ; _DWORD
        // FF 35 44 35 41 00                       push    dword_413544    ; _DWORD
        // FF 35 40 35 41 00                       push    dword_413540    ; _DWORD
        // FF 35 3C 35 41 00                       push    dword_41353C    ; _DWORD
        // FF 35 38 35 41 00                       push    dword_413538    ; _DWORD
        // FF 35 34 35 41 00                       push    dword_413534    ; _DWORD
        // FF 35 30 35 41 00                       push    dword_413530    ; _DWORD
        // FF 35 2C 35 41 00                       push    dword_41352C    ; _DWORD
        // FF 35 14 35 41 00                       push    dword_413514    ; _DWORD
        // FF 35 10 35 41 00                       push    dword_413510    ; _DWORD
        // 68 07 02 00 00                          push    207h            ; _DWORD
        $get_version = { 68 3A 01 00 00 [16-48] FF [5] FF [5] FF [5] FF [5] FF [5] FF [5] FF [5] FF [5] FF [5] FF [5] FF [5] FF [5] 68 }
    condition:
        any of them
}
