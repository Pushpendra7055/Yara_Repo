rule Backdoor_Win64_HAVOC_dll
{
    meta:
        author = "Pushpendra Bharala"
        description = "PDF resource extraction + AES decryption + process hunting"
		MD5 = "491b826822ca82fc720d40b14ce0eb42"
        confidence = "high"

    strings:

        // --- Resource extraction ---
		//lea     r8, Type        ; "PDF"
		//mov     edx, 65h ; 'e'  ; lpName
		//mov     rcx, cs:qword_18007FB60 ; hModule
		//call    cs:FindResourceW
		//mov     r15, rax
		//mov     rdx, rax        ; hResInfo
		//mov     rcx, cs:qword_18007FB60 ; hModule
		//call    cs:LoadResource
		//mov     rsi, rax
        $res_bytes = { 
            4C 8D 05 AE 2D 04 00 BA 65 00 00 00 48 8B 0D 5A 6F 07 00 FF 15 ?? ?? 04 00 4C 8B F8 48 8B D0 48 8B 0D 47 6F 07 00 FF 15 ?? ?? 04 00 48 8B F0
        }

        // --- File drop sequence ---
		//lea     rcx, [rsp+1A8h+var_138]
		//call    sub_180048970
		//mov     [rsp+1A8h+var_188], 1
		//mov     r9d, 40h ; '@'
		//mov     r8d, 20h ; ' '
		//lea     rdx, aEvidencePdf ; "./evidence.pdf"
		//lea     rcx, [rsp+1A8h+var_138]
		//call    sub_1800045F0

       $drop_bytes = { 
            C7 44 24 20 01 00 00 00 41 B9 40 00 00 00 41 B8 20 00 00 00 48 8D 15 89 2A 04 00 48 8D 4C 24 70 E8 BF B6 FF FF
        }

        // --- AES key derivation ---
		//mov     r8, [rsp+0A8h+phHash] ; hBaseData
		//lea     rax, [rsp+0A8h+phKey]
		//mov     rcx, [rsp+0A8h+phProv] ; hProv
		//xor     r9d, r9d        ; dwFlags
		//mov     edx, 6610h      ; Algid
		//mov     qword ptr [rsp+0A8h+dwFlags], rax ; phKey
		//call    cs:CryptDeriveKey

        $derive_bytes = { 
            4C 8B 44 24 48 48 8D 44 24 50 48 8B 4C 24 40 45 33 C9 BA 10 66 00 00 48 89 44 24 20 FF 15 ?? ?? 04 00
        }

        // --- Decryption call ---
		//mov     rcx, [rsp+0A8h+phKey] ; hKey
		//lea     rax, [rsp+0A8h+var_70]
		//mov     [rsp+0A8h+pdwDataLen], rax ; pdwDataLen
		//xor     r9d, r9d        ; dwFlags
		//xor     r8d, r8d        ; Final
		//mov     qword ptr [rsp+0A8h+dwFlags], r13 ; pbData
		//xor     edx, edx        ; hHash
		//call    cs:CryptDecrypt
		//mov     rcx, rbp

        $decrypt_bytes = { 
            48 8B 4C 24 50 48 8D 44 24 38 48 89 44 24 28 45 33 C9 45 33 C0 4C 89 6C 24 20 33 D2 FF 15 ?? ?? 04 00 48 8B CD
        }

        // --- Strings ---
        $dll = "simpleinjsys3.dll" ascii wide
        $forwardedExport = "WorkFoldersShell.dllCanUnloadNow" ascii wide

        // --- Process hunting ---
        $snap = "CreateToolhelp32Snapshot"
        $first = "Process32FirstW"
        $next = "Process32NextW"

    condition:
        uint16(0) == 0x5A4D and
        $res_bytes and $drop_bytes and $derive_bytes and $decrypt_bytes and
        $dll and $forwardedExport and $snap and $first and $next
}
