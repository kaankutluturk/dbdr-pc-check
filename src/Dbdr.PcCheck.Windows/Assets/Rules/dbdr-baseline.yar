rule DBDR_Remote_Process_API_Cluster : review binary_triage
{
    meta:
        description = "Multiple APIs commonly used by remote-process tooling"
        interpretation = "Review lead only; debuggers, overlays, accessibility and administration tools may match"
        profile = "dbdr-baseline-0.5"

    strings:
        $mz = { 4D 5A }
        $open_process = "OpenProcess" ascii wide
        $write_memory = "WriteProcessMemory" ascii wide
        $virtual_alloc = "VirtualAllocEx" ascii wide
        $remote_thread = "CreateRemoteThread" ascii wide
        $nt_write = "NtWriteVirtualMemory" ascii wide
        $nt_thread = "NtCreateThreadEx" ascii wide

    condition:
        $mz at 0 and 4 of ($open_process, $write_memory, $virtual_alloc, $remote_thread, $nt_write, $nt_thread)
}

rule DBDR_Manual_Map_API_Cluster : review binary_triage
{
    meta:
        description = "APIs frequently combined by manual image mappers"
        interpretation = "Review lead only; packers, launchers, overlays and security tools may match"
        profile = "dbdr-baseline-0.5"

    strings:
        $mz = { 4D 5A }
        $alloc = "VirtualAlloc" ascii wide
        $protect = "VirtualProtect" ascii wide
        $map = "NtMapViewOfSection" ascii wide
        $load = "LoadLibrary" ascii wide
        $proc = "GetProcAddress" ascii wide
        $unwind = "RtlAddFunctionTable" ascii wide
        $flush = "FlushInstructionCache" ascii wide

    condition:
        $mz at 0 and 5 of ($alloc, $protect, $map, $load, $proc, $unwind, $flush)
}

rule DBDR_Driver_Control_API_Cluster : review binary_triage
{
    meta:
        description = "Service and device APIs capable of loading or controlling drivers"
        interpretation = "Review lead only; hardware utilities, anti-cheat and administration tools may match"
        profile = "dbdr-baseline-0.5"

    strings:
        $mz = { 4D 5A }
        $create_service = "CreateService" ascii wide
        $start_service = "StartService" ascii wide
        $load_driver = "NtLoadDriver" ascii wide
        $device_io = "DeviceIoControl" ascii wide
        $service_manager = "OpenSCManager" ascii wide

    condition:
        $mz at 0 and 3 of ($create_service, $start_service, $load_driver, $device_io, $service_manager)
}

rule DBDR_Input_Hook_API_Cluster : review binary_triage
{
    meta:
        description = "Input observation and synthesis API cluster"
        interpretation = "Review lead only; accessibility, macro, overlay and peripheral tools may match"
        profile = "dbdr-baseline-0.5"

    strings:
        $mz = { 4D 5A }
        $hook = "SetWindowsHookEx" ascii wide
        $async_key = "GetAsyncKeyState" ascii wide
        $send_input = "SendInput" ascii wide
        $mouse_event = "mouse_event" ascii wide
        $keybd_event = "keybd_event" ascii wide
        $raw_input = "GetRawInputData" ascii wide

    condition:
        $mz at 0 and 4 of ($hook, $async_key, $send_input, $mouse_event, $keybd_event, $raw_input)
}

rule DBDR_Download_And_Launch_API_Cluster : review binary_triage
{
    meta:
        description = "Network retrieval combined with process-launch APIs"
        interpretation = "Review lead only; installers, launchers and update agents commonly match"
        profile = "dbdr-baseline-0.5"

    strings:
        $mz = { 4D 5A }
        $url_download = "URLDownloadToFile" ascii wide
        $winhttp = "WinHttpOpen" ascii wide
        $wininet = "InternetOpen" ascii wide
        $create_process = "CreateProcess" ascii wide
        $shell_execute = "ShellExecute" ascii wide
        $win_exec = "WinExec" ascii wide

    condition:
        $mz at 0 and 1 of ($url_download, $winhttp, $wininet) and 1 of ($create_process, $shell_execute, $win_exec)
}

rule DBDR_Anti_Analysis_API_Cluster : review binary_triage
{
    meta:
        description = "Multiple debugger and timing probes in one executable"
        interpretation = "Review lead only; protectors, DRM, anti-cheat and diagnostic tools may match"
        profile = "dbdr-baseline-0.5"

    strings:
        $mz = { 4D 5A }
        $debugger = "IsDebuggerPresent" ascii wide
        $remote_debugger = "CheckRemoteDebuggerPresent" ascii wide
        $query_process = "NtQueryInformationProcess" ascii wide
        $debug_string = "OutputDebugString" ascii wide
        $performance = "QueryPerformanceCounter" ascii wide
        $tick = "GetTickCount" ascii wide

    condition:
        $mz at 0 and 4 of ($debugger, $remote_debugger, $query_process, $debug_string, $performance, $tick)
}

rule DBDR_Process_Memory_And_Input_Cluster : review binary_triage
{
    meta:
        description = "Cross-cluster process memory access and input polling"
        interpretation = "Review lead only; debuggers, trainers, overlays, accessibility and test automation may match"
        profile = "dbdr-baseline-0.5"

    strings:
        $mz = { 4D 5A }
        $open = "OpenProcess" ascii wide
        $read = "ReadProcessMemory" ascii wide
        $write = "WriteProcessMemory" ascii wide
        $query = "NtQueryInformationProcess" ascii wide
        $async_key = "GetAsyncKeyState" ascii wide
        $key_state = "GetKeyState" ascii wide
        $raw_input = "GetRawInputData" ascii wide

    condition:
        $mz at 0 and 2 of ($open, $read, $write, $query) and 1 of ($async_key, $key_state, $raw_input)
}

rule DBDR_Known_Vulnerable_Driver_Loader_Cluster : review binary_triage
{
    meta:
        description = "Known vulnerable-driver filename combined with service or device-control APIs"
        interpretation = "Review lead only; hardware diagnostics and security research tools may contain the same names"
        profile = "dbdr-baseline-0.5"

    strings:
        $mz = { 4D 5A }
        $driver_1 = "iqvw64e.sys" ascii wide nocase
        $driver_2 = "gdrv.sys" ascii wide nocase
        $driver_3 = "RTCore64.sys" ascii wide nocase
        $driver_4 = "dbutil_2_3.sys" ascii wide nocase
        $driver_5 = "WinRing0x64.sys" ascii wide nocase
        $service = "CreateService" ascii wide
        $start = "StartService" ascii wide
        $device = "DeviceIoControl" ascii wide
        $privilege = "SeLoadDriverPrivilege" ascii wide
        $load = "NtLoadDriver" ascii wide

    condition:
        $mz at 0 and 1 of ($driver_*) and 2 of ($service, $start, $device, $privilege, $load)
}

rule DBDR_Artifact_Removal_API_Cluster : review binary_triage
{
    meta:
        description = "Multiple APIs capable of removing Windows execution-history artifacts"
        interpretation = "Review lead only; maintenance, privacy and administrative utilities may match"
        profile = "dbdr-baseline-0.5"

    strings:
        $mz = { 4D 5A }
        $clear_a = "ClearEventLogA" ascii wide
        $clear_w = "ClearEventLogW" ascii wide
        $evt_clear = "EvtClearLog" ascii wide
        $delete_usn = "FSCTL_DELETE_USN_JOURNAL" ascii wide
        $delete_file = "DeleteFile" ascii wide
        $set_zero = "SetFileInformationByHandle" ascii wide

    condition:
        $mz at 0 and 3 of ($clear_a, $clear_w, $evt_clear, $delete_usn, $delete_file, $set_zero)
}
