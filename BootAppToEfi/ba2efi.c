#include "ba2efi.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <intrin.h>

typedef void (*fptrArchSetDescriptorTableContext)(void* DescriptorTable);

#define SHELLCODE_VARIABLE(name) __declspec(allocate(".text")) const uint8_t name ## []

#ifdef _M_X64
#pragma section(".text")
// for one-file purpose...
SHELLCODE_VARIABLE(bArchSetDescriptorTableContext) = {
	0x0F, 0x01, 0x11,							// lgdt [rcx]
	0x0F, 0x01, 0x59, 0x0A,						// lidt [rcx+0Ah]
	0x0F, 0x00, 0x51, 0x14,						// lldt [rcx+14h]

	// the original uses a full 64-bit mov here,
	// lea should do just fine, and make this position independant
	0x48, 0x8D, 0x15, 0x09, 0x00, 0x00, 0x00,	// lea rdx, SecondHalf

	0x48, 0x0F, 0xB7, 0x41, 0x16,				// movzx rax, word [rcx+16h]
	0x50,										// push rax
	0x52,										// push rdx
	0x48, 0xCB,									// retfq
	// SecondHalf:
	// original restores gs before fs,
	// i decided to do the restores in structure-offset order for aesthetics.
	0x8E, 0x59, 0x18,							// mov ds, word [rcx+18h]
	0x8E, 0x41, 0x1A,							// mov es, word [rcx+1Ah]
	0x8E, 0x61, 0x1C,							// mov fs, word [rcx+1Ch]
	0x8E, 0x69, 0x1E,							// mov gs, word [rcx+1Eh]
	0x8E, 0x51, 0x20,							// mov ss, word [rcx+20h]
	0xC3										// retn
};
#define ArchSetDescriptorTableContext(x) \
	((fptrArchSetDescriptorTableContext)bArchSetDescriptorTableContext) \
		(x)
#endif

void SwitchToFirmwareContext(void* FirmwareData) {
	// Reinterpret the firmware data as pointer to bytes.
	uint8_t* FwData8 = (uint8_t*)FirmwareData;
#ifdef _M_X64
	// x64 stores additional state in the firmware data at specific offsets.
	// Set page table base from the firmware data.
	uint64_t cr3 = *(uint64_t*)&FwData8[0x1C];
	__writecr3(cr3);
	// Set GDT/IDT/LDT and segment registers from the firmware data.
	ArchSetDescriptorTableContext(&FwData8[0x24]);
	// Enable interrupts.
	_enable();
#elif _M_IX86
	// Disable paging.
	__writecr0(__readcr0() & ~0x80000000);
	// Disable PAE.
	__writecr4(__readcr4() & ~0x20);
	// Enable interrupts.
	_enable();
#elif _M_ARM
#error "Not implemented" // there's a chainloader already for ARMv7, TODO: port that?
#elif _M_ARM64
#error "Not implemented (yet)" // original code here literally uses a switch instead of shifting right, lol. TODO: reimplement
#else
#error "Unsupported architecture"
#endif
}

static inline __forceinline void WaitForInterrupt() {
#if defined(_M_X64) || defined(_M_IX86)
	__halt();
#elif defined(_M_ARM) || defined(_M_ARM64)
	__wfi();
#else
#error "Unsupported architecture"
#endif
}

NTSTATUS BootApplicationEntryPoint(__inout PBOOT_APPLICATION_PARAMETERS Parameters) {
	// Get the offset to the firmware data.
	uint32_t FirmwareDataOffset = *((uint32_t*)((size_t)Parameters + FIRMWARE_DATA_OFFSET));
	// Get a pointer to the firmware data.
	size_t* FirmwareData = (size_t*)((size_t)Parameters + FirmwareDataOffset);

	// Get the EFI system table and EFI image handle.
	// Please note:
	// The start of the FIRMWARE_DATA structure is architecture independent: uint32_t Version; EFI_HANDLE ImageHandle; EFI_SYSTEM_TABLE* SystemTable
	// On 64-bit architectures there is padding between the first two elements; so interpreting as an array of size_t will work fine.
	EFI_HANDLE ImageHandle = (EFI_HANDLE)FirmwareData[1];
	EFI_SYSTEM_TABLE* SystemTable = (EFI_SYSTEM_TABLE*)FirmwareData[2];

	// Switch to the firmware context.
	SwitchToFirmwareContext(FirmwareData);

	// In the firmware context: call the EFI entry point.
	EfiMain(ImageHandle, SystemTable);

	// We don't want to return to the caller.
	while (1) WaitForInterrupt();
}