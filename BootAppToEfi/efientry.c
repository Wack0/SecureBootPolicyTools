#include "efientry.h"

EFI_STATUS EfiMain(__in EFI_HANDLE ImageHandle, __in EFI_SYSTEM_TABLE* SystemTable) {
	SystemTable->ConOut->OutputString(SystemTable->ConOut, L"hello world from windows boot application!");
	return EFI_SUCCESS;
}