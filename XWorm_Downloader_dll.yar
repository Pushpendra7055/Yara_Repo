rule XWorm_Downloader_dll
{
    
    meta:
        author = "Pushpendra Bharala"
        description = "Detects WinINet-based downloader with catbox usage and in-memory allocation pattern"
		MD5 = "30AD3C31AF271DBBAB1CF55A41493BE2"
        confidence = "high"

    strings:
        // Core strings
        $hostfxr = "get_hostfxr_path" ascii wide
        $runkey  = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide

        // Split domain (as provided)
        $cat1 = "files.ca" ascii
        $cat2 = "tbox.moe" ascii

        // Networking APIs
        $inet1 = "InternetOpenUrlA" ascii
        $inet2 = "InternetReadFile" ascii

        //mov     [rsp+200h+arg_10], rdi
        //xor     ecx, ecx        ; lpAddress
        //mov     r9d, 4          ; flProtect
        //mov     r8d, 3000h      ; flAllocationType
        //call    cs:VirtualAlloc
        //mov     rdi, rax
        //mov     rcx, rsi        ; hFile
        //test    rax, rax

        $alloc_pattern = { 
           33 C9 41 B9 04 00 00 00 41 B8 00 30 00 00 FF 15 ?? ?? 00 00 48 8B F8 48 8B CE 48 85 C0
        }

        //lea     r9, [rsp+200h+pbDebuggerPresent]
        //mov     r8d, 10000h     ; dwNumberOfBytesToRead
        //mov     rdx, rdi        ; lpBuffer
        //xor     ebx, ebx
        //call    cs:InternetReadFile
        //test    eax, eax

        $read_pattern = {
           4C 8D 4C 24 30 41 B8 00 00 01 00 48 8B D7 33 DB FF 15 ?? ?? 00 00 85 C0
        }

    condition:
	uint16(0) == 0x5A4D and
	        ( $hostfxr or $runkey ) and
            ( $cat1 and $cat2 and $inet1 and $inet2 ) and
            ( $alloc_pattern ) or
            ( $read_pattern ) 
}
