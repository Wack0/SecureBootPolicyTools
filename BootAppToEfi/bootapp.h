// Boot Application Headers

#pragma once

// Source Code Annotation Language.
#include <sal.h>

// NTSTATUS definitions.
typedef _Return_type_success_(return >= 0) long NTSTATUS;
#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

#include <ntstatus.h>

// Boot application parameters.
#define FIRMWARE_DATA_OFFSET 0x30 // Same offset for all architectures.
typedef struct _BOOT_APPLICATION_PARAMETERS* PBOOT_APPLICATION_PARAMETERS;

/// <summary>Entry point for a Windows Boot Application executable.</summary>
/// <param name="Parameters">Parameters passed to the boot application.</param>
/// <returns>NT status code.</returns>
NTSTATUS BootApplicationEntryPoint(__inout PBOOT_APPLICATION_PARAMETERS Parameters);