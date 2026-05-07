rule RunPE_Schtasks_Persistence_Loader
{
    meta:
        author = "Pushpendra Bharala"
        description = "Detects RunPE style loader resolving injection APIs dynamically and building schtasks persistence command"
        date = "2026-05-07"
        version = "1.0"
        category = "malware.loader"

    strings:

        //loc_62C42E0B:
        //mov     [esp+778h+lpProcName], offset aVirtualallocex ; "VirtualAllocEx"
        //mov     eax, [ebp+hModule]
        //mov     [esp+778h+lpLibFileName], eax ; hModule
        //mov     eax, ds:__imp_GetProcAddress
        //call    eax ; __imp_GetProcAddress
        //sub     esp, 8
        //mov     [ebp+var_34], eax
        //mov     [esp+778h+lpProcName], offset aWriteprocessme ; "WriteProcessMemory"
        //mov     eax, [ebp+hModule]
        //mov     [esp+778h+lpLibFileName], eax ; hModule
        //mov     eax, ds:__imp_GetProcAddress
        //call    eax ; __imp_GetProcAddress
        //sub     esp, 8
        //mov     [ebp+var_38], eax
        //mov     [esp+778h+lpProcName], offset aReadprocessmem ; "ReadProcessMemory"
        //mov     eax, [ebp+hModule]
        //mov     [esp+778h+lpLibFileName], eax ; hModule

        $runpe_api_resolve_1 = {C7 44 24 04 ?? ?? ?? ?? 8B 45 D0 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 CC C7 44 24 04 ?? ?? ?? ?? 8B 45 D0 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 C8 C7 44 24 04 ?? ?? ?? ?? 8B 45 D0 89 04 24}

        //mov     [ebp+var_44], eax
        //mov     [esp+778h+lpProcName], offset aResumethread ; "ResumeThread"
        //mov     eax, [ebp+hModule]
        //mov     [esp+778h+lpLibFileName], eax ; hModule
        //mov     eax, ds:__imp_GetProcAddress
        //call    eax ; __imp_GetProcAddress
        //sub     esp, 8
        //mov     [ebp+var_48], eax
        //mov     [esp+778h+lpProcName], offset aCreateprocessa ; "CreateProcessA"
        //mov     eax, [ebp+hModule]
        //mov     [esp+778h+lpLibFileName], eax ; hModule
        //mov     eax, ds:__imp_GetProcAddress
        //call    eax ; __imp_GetProcAddress
        //sub     esp, 8
        //mov     [ebp+var_4C], eax
        //mov     [esp+778h+lpProcName], offset aTerminateproce ; "TerminateProcess"
        //mov     eax, [ebp+hModule]

        $runpe_api_resolve_2 = {89 45 BC C7 44 24 04 ?? ?? ?? ?? 8B 45 D0 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 B8 C7 44 24 04 ?? ?? ?? ?? 8B 45 D0 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 B4 C7 44 24 04 ?? ?? ?? ?? 8B 45 D0 89}

        loc_62C433FD:
        //mov     eax, [ebp+var_2C]
        //lea     edx, [eax+eax]
        //mov     eax, [ebp+var_7C]
        //add     eax, edx
        //movzx   eax, word ptr [eax]
        //shr     ax, 0Ch
        //cmp     ax, 3
        //jnz     loc_62C434BE

        $reloc_check = { 8B 45 D4 8D 14 00 8B 45 84 01 D0 0F B7 00 66 C1 E8 0C 66 83 F8 03 0F 85 }

        //lea     eax, [ebp+Buffer]
        //mov     [esp+0CA8h+nSize], eax
        //mov     [esp+0CA8h+lpFilename], offset aSSchtasksExe ; "%s\\schtasks.exe"
        //lea     eax, [ebp+ApplicationName]
        //mov     [esp+0CA8h+hModule], eax
        //call    sub_62C5F140
        //lea     edx, [ebp+CommandLine]
        //mov     eax, 0
        //mov     ecx, 0C3h
        //mov     edi, edx
        //rep stosd
        //lea     eax, [ebp+FileName]
        //mov     [esp+0CA8h+bInheritHandles], eax
        //lea     eax, [ebp+var_6EA]
        //mov     [esp+0CA8h+lpThreadAttributes], eax
        //lea     eax, [ebp+ApplicationName]
        //mov     [esp+0CA8h+nSize], eax
        //mov     [esp+0CA8h+lpFilename], offset aSCreateTnSTrSS ; "\"%s\" /Create /TN %s /TR \"\\\"%s\\\""... 
        //lea     eax, [ebp+CommandLine]

        $schtask_builder = { 8D 85 D0 F3 FF FF 89 44 24 08 C7 44 24 04 ?? ?? ?? ?? 8D 85 D4 F4 FF FF 89 04 24 E8 ?? ?? ?? ?? 8D 95 D8 F5 FF FF B8 00 00 00 00 B9 C3 00 00 00 89 D7 F3 AB 8D 85 94 FB FF FF 89 44 24 10 8D 85 16 F9 FF FF 89 44 24 0C 8D 85 D4 F4 FF FF 89 44 24 08 C7 44 24 04 ?? ?? ?? ?? 8D 85 D8 F5 FF FF }

       
     condition:
        uint16(0) == 0x5A4D and
        all of them
}
