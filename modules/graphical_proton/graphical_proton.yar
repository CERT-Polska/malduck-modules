rule win_graphical_proton_drop_packed {
    meta:
        author = "Military Counterintelligence Service / CERT Polska"
        reference = "Graphical Proton packed drop"
    strings:
        // 42 8A 04 27                             mov     al, [rdi+r12]
        // 42 32 04 26                             xor     al, [rsi+r12]
        // 42 88 44 25 00                          mov     [rbp+r12+0], al

        // 8A 04 37                                mov     al, [rdi+rsi]
        // 41 32 04 34                             xor     al, [r12+rsi]
        // 88 44 35 00                             mov     [rbp+rsi+0], al
        $op_add_b64_buffers0 = { 42 8A 04 27 42 32 04 26 42 88 44 25 00 }
        $op_add_b64_buffers1 = { 8A 04 37 41 32 04 34 88 44 35 00 }

        // C1 C0 05                                rol     eax, 5
        // C1 C2 08                                rol     edx, 8
        // 44 31 C0                                xor     eax, r8d
        // 41 C1 C0 10                             rol     r8d, 10h
        // 31 CA                                   xor     edx, ecx
        // 01 C1                                   add     ecx, eax
        // C1 C0 07                                rol     eax, 7
        // 41 01 D0                                add     r8d, edx
        // C1 C2 0D                                rol     edx, 0Dh
        // 31 C8                                   xor     eax, ecx
        // 44 31 C2                                xor     edx, r8d
        // C1 C1 10                                rol     ecx, 10h
        $op_rol_crypt = { C1 C0 05 C1 C2 08 [2-3] (41 C1 C0 10 | C1 C1 10) }

        // 8B 14 07                                mov     edx, [rdi+rax]
        // 33 54 05 00                             xor     edx, [rbp+rax+0]
        // 89 14 07                                mov     [rdi+rax], edx
        $op_xor_keys0 = { 8B 14 0? (33 54 05 00 | 89 14 0? ) 89 14 0? }

        // 42 8B 04 2E                             mov     eax, [rsi+r13]
        // 42 33 44 2D 00                          xor     eax, [rbp+r13+0]
        // 42 89 04 2E                             mov     [rsi+r13], eax
        $op_xor_keys1 = { 4? 8B ?? ?? 4? 33 ?4 ?? 00 4? 89 ?? ?? }

        // 8B 44 15 00                             mov     eax, [rbp+rdx+0]
        // 41 33 44 15 00                          xor     eax, [r13+rdx+0]
        // 89 44 15 00                             mov     [rbp+rdx+0], eax
        $op_xor_keys2 = { 8b 44 15 00 4? 33 44 ?? 00 89 44 15 00 }

        // 41 FE 46 1F                             inc     byte ptr [r14+1Fh]
        // 75 55                                   jnz     short loc_2AB0460E2
        $op_derive_key = { FE 4? 1f (75 | 0F 85) }


        // 48 8D AF 08 01 00 00                    lea     rbp, [rdi+108h]
        // 4C 8D B6 08 01 00 00                    lea     r14, [rsi+108h]
        $op_move_section_offset = { 4? 8d ?? 08 01 00 00 }
    condition:
        $op_rol_crypt and $op_derive_key or 3 of them
}


rule win_graphical_proton {
    meta:
        author = "Military Counterintelligence Service / CERT Polska"
        reference = "Graphical Proton FULLRIG tool"

    strings:
        // C1 E9 1B                                shr     ecx, 1Bh
        // 48 8B 44 24 08                          mov     rax, [rsp+30h+var_28]
        // 8B 50 04                                mov     edx, [rax+4]
        // C1 E2 05                                shl     edx, 5
        // 09 D1                                   or      ecx, edx
        // 48 8B 44 24 08                          mov     rax, [rsp+30h+var_28]
        $op_string_crypt = { c1 e? (1b | 18 | 10 | 13 | 19 | 10) 48 [4] 8b [2] c1 e? (05 | 08 | 10 | 0d | 07) 09 ?? 48 }

        // 48 05 20 00 00 00                       add     rax, 20h ; ' '
        // 48 89 C1                                mov     rcx, rax
        // 48 8D 15 0A A6 0D 00                    lea     rdx, unk_14011E546
        // 41 B8 30 00 00 00                       mov     r8d, 30h ; '0'
        // E8 69 B5 FE FF                          call    sub_14002F4B0
        // 48 8B 44 24 30                          mov     rax, [rsp+88h+var_58]

        // 48 05 40 00 00 00                       add     rax, 40h ; '@'
        // 48 89 C1                                mov     rcx, rax
        // 48 8D 15 1B A6 0D 00                    lea     rdx, unk_14011E577
        // 41 B8 70 01 00 00                       mov     r8d, 170h
        // E8 49 B5 FE FF                          call    sub_14002F4B0
        // 48 8B 44 24 30                          mov     rax, [rsp+88h+var_58]

        // 48 05 60 00 00 00                       add     rax, 60h ; '`'
        // 48 89 C1                                mov     rcx, rax
        // 48 8D 15 6C A7 0D 00                    lea     rdx, unk_14011E6E8
        // 41 B8 2F 00 00 00                       mov     r8d, 2Fh ; '/'
        // E8 29 B5 FE FF                          call    sub_14002F4B0
        // 48 8B 44 24 30                          mov     rax, [rsp+88h+var_58]

        // 48 05 80 00 00 00                       add     rax, 80h
        // 48 89 C1                                mov     rcx, rax
        // 48 8D 15 7C A7 0D 00                    lea     rdx, unk_14011E718
        // 41 B8 2F 00 00 00                       mov     r8d, 2Fh ; '/'
        // E8 09 B5 FE FF                          call    sub_14002F4B0
        // 48 8B 44 24 30                          mov     rax, [rsp+88h+var_58]

        // 48 05 A0 00 00 00                       add     rax, 0A0h
        $op_decrypt_config0 = {
            48 8D [10-50]
            48 05 20 00 00 00 48 89 C1 48 [6] 41 B8 ?? ?? 00 00 E8 [4] 48 [4]
            48 05 40 00 00 00 48 89 C1 48 [6] 41 B8 ?? ?? 00 00 E8 [4] 48 [4]
            48 05 60 00 00 00 48 89 C1 48 [6] 41 B8 ?? ?? 00 00 E8 [4] 48 [4]
            48 05 80 00 00 00 48 89 C1 48 [6] 41 B8 ?? ?? 00 00 E8 [4] 48 [4]
            48 05 A0 00 00 00
        }

        $op_decrypt_config1 = {
            48 8D [10-50]
            48 83 ?? 20 48 [6] 41 B8 ?? ?? 00 00 48 89 C1 48 [3] E8 [4-9] 48 [3]
            48 83 ?? 40 48 [6] 41 B8 ?? ?? 00 00 48 89 C1 48 [3] E8 [4-9] 48 [3]
            48 83 ?? 60 48 [6] 41 B8 ?? ?? 00 00 48 89 C1 48 [3] E8 [4-9] 48 [3]
            48 83 ?? 80 48 [6] 41 B8 ?? ?? 00 00 48 89 C1 48 [3] E8 [4-9] 48 [3]
            48 83 ?? A0
        }

        $op_decrypt_config2 = {
            48 8D [10-50]
            48 83 ?? 20 48 [6] 41 B8 ?? ?? 00 00 48 89 C1 48 [3] E8 [4-9] 48 [3]
            48 83 ?? 40 48 [6] 41 B8 ?? ?? 00 00 48 89 C1 48 [3] E8 [4-9] 48 [3]
            48 83 ?? 60 48 [6] 41 B8 ?? ?? 00 00 48 89 C1 48 [3] E8 [4-9] 48 [3]
            48 83 ?? 80 48 [6] 41 B8 ?? ?? 00 00 48 89 C1 48 [3] E8 [4-9] 48
        }

    condition:
        2 of them
}
