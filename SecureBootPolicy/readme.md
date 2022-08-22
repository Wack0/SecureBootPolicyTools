# Secure Boot Policy Builder
This is a library and application coded in C# allowing the creation of binary Secure Boot Policy files from an XML format similar to the SiPolicy/CiPolicy XML format. 
Two examples are included: 
- `SecureBootPolicyDefault.xml` is the default Secure Boot Policy included in the resource data of  `bootmgr` starting from RS2 (as far as it can be replicated; publisher is different due to restrictions, and the CanUpdate GUIDs are not present as they were only used by win8beta) 
- `SecureBootPolicyExample.xml` gives an example of a custom policy touching on all available parameters. 

## Why?
`bootmgr` before RS1 can load Secure Boot policies that are signed by PK, with restrictions. 
Therefore if you control PK you can control the Secure Boot policy. 
A Secure Boot policy can control various things including the valid signers for every PE checked by boot applications (including `bootmgr`, `winload`, `hvloader`, `tcblaunch` etc), and by `ci.dll` and `skci.dll`. 
Also, Secure Boot policy binary used by NT gets protected by PatchGuard. 
- Want to add your certs to be valid for WinTcb protected process? You can! 
- Want to add your certs to Microsoft or Windows signing level and therefore run code in IUM/VTL1 (by signing with `szOID_IUM_SIGNING` EKU), or in a VSM enclave (by signing with `szOID_ENCLAVE_SIGNING` EKU), or run VTL1 driver (by signing with `szOID_NT5_CRYPTO` EKU)? You can! 
- Want to add your certs to be valid for boot applications and therefore set up a Linux dualboot through `bootmgr` (which would allow for running shim/grub with bitlocker keys derived and in memory)? You can!

## Signing Policy
Signing is exactly the same as [SiPolicy/CiPolicy](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/use-signed-policies-to-protect-windows-defender-application-control-against-tampering).
