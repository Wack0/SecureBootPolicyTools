# SecureBootPolicyTools

Tools for creating and using Secure Boot policies.

bootmgr prior to RS1 accepts Secure Boot policies signed by PK.

Thus, if you control PK, you control what Windows Code Integrity trusts. Sign your own Windows Boot Application; hypervisor; securekernel; driver (VTL0/VTL1); protected process; PPL.

## Included tools

- `SecureBootPolicy`: library and compiler for Secure Boot policies. Includes three example policies:
    - `SecureBootPolicyDefault.xml` reimplements as much as possible the default Secure Boot policy included in bootmgr starting from RS2.
    - `SecureBootPolicyDefaultWithSigners.xml` is the same as above that also reimplements the default signers trusted by CI for easy extensibility
    - `SecureBootPolicyExample.xml` adds a custom signer. Replace the TBS hash and enjoy your trusted binaries.
- `EfiInstallPolicy`: EFI application to install a signed Secure Boot policy into UEFI non-volatile variables.
- `BootAppToEfi`: Windows Boot Application that switches back to the EFI environment and calls `EfiMain()`.

## Note

I am not responsible for anything that may happen to your systems/VMs when using these tools; after all, you control the keys!
