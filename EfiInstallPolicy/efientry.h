// EFI headers.
#pragma once

#include <sal.h>
#include "efi.h"

/// <summary>EFI entry point</summary>
/// <param name="ImageHandle">Firmware allocated handle for the EFI boot application (not this application)</param>
/// <param name="SystemTable">Pointer to the EFI system table</param>
/// <returns>EFI status code.</returns>
EFI_STATUS EfiMain(__in EFI_HANDLE ImageHandle, __in EFI_SYSTEM_TABLE* SystemTable);