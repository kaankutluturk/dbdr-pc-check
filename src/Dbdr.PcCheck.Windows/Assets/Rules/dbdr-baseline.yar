rule DBDR_Remote_Process_API_Cluster : review binary_triage
{
    meta:
        description = "Multiple APIs commonly used by remote-process tooling"
        interpretation = "Review lead only; debuggers, overlays, accessibility and administration tools may match"
        profile = "dbdr-baseline-0.3"

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
