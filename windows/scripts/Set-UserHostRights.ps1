[CmdletBinding()]
param([Parameter(Mandatory)][string]$WindowsAccount)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Administrators PowerShell is required.'
}

if (-not ('AionUiPortal.LsaRights' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace AionUiPortal {
  public static class LsaRights {
    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES {
      public int Length; public IntPtr RootDirectory; public IntPtr ObjectName;
      public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern uint LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES attributes, uint access, out IntPtr handle);
    [DllImport("advapi32.dll")]
    static extern uint LsaAddAccountRights(IntPtr handle, IntPtr sid, LSA_UNICODE_STRING[] rights, uint count);
    [DllImport("advapi32.dll")]
    static extern uint LsaRemoveAccountRights(IntPtr handle, IntPtr sid, [MarshalAs(UnmanagedType.Bool)] bool allRights, LSA_UNICODE_STRING[] rights, uint count);
    [DllImport("advapi32.dll")]
    static extern uint LsaEnumerateAccountRights(IntPtr handle, IntPtr sid, out IntPtr rights, out uint count);
    [DllImport("advapi32.dll")] static extern uint LsaNtStatusToWinError(uint status);
    [DllImport("advapi32.dll")] static extern uint LsaFreeMemory(IntPtr buffer);
    [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr handle);

    static void Check(uint status, string operation) {
      if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status), operation);
    }
    static IntPtr Open() {
      var attributes = new LSA_OBJECT_ATTRIBUTES();
      attributes.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
      IntPtr handle; Check(LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x00000810, out handle), "LsaOpenPolicy");
      return handle;
    }
    static GCHandle PinSid(string sidValue, out IntPtr pointer) {
      var sid = new SecurityIdentifier(sidValue);
      var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
      var pin = GCHandle.Alloc(bytes, GCHandleType.Pinned); pointer = pin.AddrOfPinnedObject(); return pin;
    }
    static LSA_UNICODE_STRING MakeString(string value) {
      var result = new LSA_UNICODE_STRING(); result.Buffer = Marshal.StringToHGlobalUni(value);
      result.Length = checked((ushort)(value.Length * 2)); result.MaximumLength = checked((ushort)(result.Length + 2)); return result;
    }
    public static void Add(string sidValue, string[] names) {
      IntPtr sidPointer; var pin = PinSid(sidValue, out sidPointer); IntPtr policy = IntPtr.Zero;
      var rights = new LSA_UNICODE_STRING[names.Length];
      try {
        for (int i=0; i<names.Length; i++) rights[i] = MakeString(names[i]);
        policy = Open(); Check(LsaAddAccountRights(policy, sidPointer, rights, (uint)rights.Length), "LsaAddAccountRights");
      } finally {
        for (int i=0; i<rights.Length; i++) if (rights[i].Buffer != IntPtr.Zero) Marshal.FreeHGlobal(rights[i].Buffer);
        if (policy != IntPtr.Zero) LsaClose(policy); pin.Free();
      }
    }
    public static void Remove(string sidValue, string[] names) {
      IntPtr sidPointer; var pin = PinSid(sidValue, out sidPointer); IntPtr policy = IntPtr.Zero;
      var rights = new LSA_UNICODE_STRING[names.Length];
      try {
        for (int i=0; i<names.Length; i++) rights[i] = MakeString(names[i]);
        policy = Open(); Check(LsaRemoveAccountRights(policy, sidPointer, false, rights, (uint)rights.Length), "LsaRemoveAccountRights");
      } finally {
        for (int i=0; i<rights.Length; i++) if (rights[i].Buffer != IntPtr.Zero) Marshal.FreeHGlobal(rights[i].Buffer);
        if (policy != IntPtr.Zero) LsaClose(policy); pin.Free();
      }
    }
    public static string[] Enumerate(string sidValue) {
      IntPtr sidPointer; var pin = PinSid(sidValue, out sidPointer); IntPtr policy = IntPtr.Zero; IntPtr buffer = IntPtr.Zero;
      try {
        policy = Open(); uint count; uint status = LsaEnumerateAccountRights(policy, sidPointer, out buffer, out count); Check(status, "LsaEnumerateAccountRights");
        var result = new List<string>(); int size = Marshal.SizeOf(typeof(LSA_UNICODE_STRING));
        for (uint i=0; i<count; i++) {
          var item = (LSA_UNICODE_STRING)Marshal.PtrToStructure(IntPtr.Add(buffer, checked((int)i * size)), typeof(LSA_UNICODE_STRING));
          result.Add(Marshal.PtrToStringUni(item.Buffer, item.Length / 2));
        }
        return result.ToArray();
      } finally {
        if (buffer != IntPtr.Zero) LsaFreeMemory(buffer); if (policy != IntPtr.Zero) LsaClose(policy); pin.Free();
      }
    }
  }
}
'@
}

$resolvedAccount = $WindowsAccount
if ($resolvedAccount.StartsWith('.\')) { $resolvedAccount = $env:COMPUTERNAME + $resolvedAccount.Substring(1) }
$account = New-Object Security.Principal.NTAccount($resolvedAccount)
$sid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
$required = @('SeBatchLogonRight', 'SeDenyRemoteInteractiveLogonRight')
[AionUiPortal.LsaRights]::Add($sid, $required)
$actual = @([AionUiPortal.LsaRights]::Enumerate($sid))
$interactiveDeny = 'SeDenyInteractiveLogonRight'
if ($interactiveDeny -in $actual) { [AionUiPortal.LsaRights]::Remove($sid, @($interactiveDeny)) }
$actual = @([AionUiPortal.LsaRights]::Enumerate($sid))
$missing = @($required | Where-Object { $_ -notin $actual })
if ($missing.Count -ne 0 -or $interactiveDeny -in $actual) { throw "Account rights verification failed for ${sid}." }
Write-Host "Verified batch-logon plus RDP deny rights for $WindowsAccount ($sid); local interactive logon remains allowed by operator decision."
