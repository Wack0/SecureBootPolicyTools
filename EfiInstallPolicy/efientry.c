#include "efientry.h"
#include "SecureBootPolicy.h"
#include <stdbool.h>

static const EFI_GUID EfiLoadedImageProtocolGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
static const EFI_GUID EfiFileSystemProtocolGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
static const EFI_GUID EfiFileInfoGuid = EFI_FILE_INFO_ID;
static const EFI_GUID EfiMicrosoftVendorGuid = { 0x77FA9ABD, 0x0359, 0x4D32, {0xBD, 0x60, 0x28, 0xF4, 0xE7, 0x8F, 0x78, 0x4B} };

static SIMPLE_TEXT_OUTPUT_INTERFACE* g_ConOut;

static CHAR16* WcsChr(_In_z_ CHAR16* Buffer, __in CHAR16 Character) {
	while (Buffer[0] != 0) {
		if (Buffer[0] == Character) return Buffer;
		Buffer++;
	}
	return NULL;
}

static int MemCmp(_In_reads_bytes_(Length) const void* pFirst, _In_reads_bytes_(Length) const void* pSecond, __in UINTN Length) {
	const UINT8 * pFirst8 = pFirst, * pSecond8 = pSecond;
	while (Length != 0) {
		int result = pFirst8[0] - pSecond8[0];
		if (result != 0) return result;
		pFirst8++;
		pSecond8++;
		Length--;
	}
	return 0;
}

// Boyer-Moore Horspool algorithm, adapted from http://www-igm.univ-mlv.fr/~lecroq/string/node18.html#SECTION00180
_Success_(return != NULL) UINT8* MemMem(_In_reads_(size) UINT8* startPos, _In_reads_bytes_(patternSize) const void* pattern, __in UINTN size, __in UINTN patternSize)
{
	const UINT8* patternc = (const UINT8*)pattern;
	UINTN table[1 << (sizeof(UINT8) * 8)];

	//Preprocessing
	for (UINTN i = 0; i < 256; i++)
		table[i] = patternSize;
	for (UINTN i = 0; i < patternSize - 1; i++)
		table[patternc[i]] = patternSize - i - 1;

	//Searching
	UINTN j = 0;
	while (j <= size - patternSize)
	{
		UINT8 c = startPos[j + patternSize - 1];
		if (patternc[patternSize - 1] == c && MemCmp(pattern, startPos + j, patternSize - 1) == 0)
			return startPos + j;
		j += table[c];
	}

	return NULL;
}

_Success_(return != NULL) static CHAR16* GetLoadOptionArgument(__in EFI_LOADED_IMAGE_PROTOCOL* LoadedImage) {
	UINT16* LoadOption = (UINT16*) LoadedImage->LoadOptions;
	UINT32 Length = LoadedImage->LoadOptionsSize;

	if (LoadOption == NULL) return NULL;
	if (Length < sizeof(L"\\a.efi")) return NULL;
	
	// Check that this looks like a path.
	if (LoadOption[0] < L' ' || LoadOption[1] == 0) return NULL;
	
	// Get the first argument.
	UINT16* Arg1 = WcsChr(LoadOption, L' ');
	if (Arg1 == NULL) return NULL;
	Arg1++;
	
	// If there's more than one argument, null terminate after the first.
	UINT16* Arg2 = WcsChr(Arg1, L' ');
	if (Arg2 != NULL) Arg2[0] = 0;

	return Arg1;
}

_Success_(return == EFI_SUCCESS) static EFI_STATUS FileOpenRead(__out EFI_FILE_PROTOCOL** VolumeFile, __in EFI_FILE_PROTOCOL* VolumeRoot, __in CHAR16* Path) {
	return VolumeRoot->Open(VolumeRoot, VolumeFile, Path, EFI_FILE_MODE_READ, 0);
}

static void PrintOpenSuccess(__in CHAR16* Path) {
	g_ConOut->OutputString(g_ConOut, L"Opened ");
	g_ConOut->OutputString(g_ConOut, Path);
	g_ConOut->OutputString(g_ConOut, L"\r\n");
}

_Success_(return == EFI_SUCCESS) static EFI_STATUS TryOpenPolicy(__out EFI_FILE_PROTOCOL** VolumeFile, __in EFI_FILE_PROTOCOL* VolumeRoot, __in EFI_LOADED_IMAGE_PROTOCOL* LoadedImage) {
	EFI_STATUS Status = EFI_SUCCESS;

	// First, check the EFI_LOAD_OPTION for a path to use.
	CHAR16* ParameterPath = GetLoadOptionArgument(LoadedImage);
	if (ParameterPath != NULL) {
		Status = FileOpenRead(VolumeFile, VolumeRoot, ParameterPath);
		if (Status == EFI_SUCCESS) {
			PrintOpenSuccess(ParameterPath);
			return Status;
		}
	}

	// Try some hardcoded paths.
	const CHAR16* const KnownPaths[] = {
		L"\\SecureBootPolicy.p7b",
		L"\\SecureBootPolicy.bin.p7",
		// L"\\EFI\\Microsoft\\Boot\\SecureBootPolicy.p7b", // Do not use this, RS1+ bootmgr uses this.
		L"\\EFI\\Microsoft\\Boot\\SecureBootPolicy.bin.p7",
		L"\\EFI\\Boot\\SecureBootPolicy.p7b",
		L"\\EFI\\Boot\\SecureBootPolicy.bin.p7"
	};
	for (UINT8 i = 0; i < sizeof(KnownPaths) / sizeof(*KnownPaths); i++) {
		Status = FileOpenRead(VolumeFile, VolumeRoot, (CHAR16*) KnownPaths[i]);
		if (Status == EFI_SUCCESS) {
			PrintOpenSuccess(KnownPaths[i]);
			return Status;
		}
	}

	g_ConOut->OutputString(g_ConOut, L"Could not open any policy file\r\n");
	return Status;
}

_Success_(return == EFI_SUCCESS) static EFI_STATUS GetFileInfo(__in EFI_BOOT_SERVICES* BS, __in EFI_FILE_PROTOCOL* File, __out EFI_FILE_INFO** FileInfo) {
	EFI_FILE_INFO* LocalInfo;
	UINTN BufferSize = 0;
	// Get the required buffer size.
	EFI_STATUS Status = File->GetInfo(File, (EFI_GUID*) &EfiFileInfoGuid, &BufferSize, NULL);
	if (Status != EFI_BUFFER_TOO_SMALL) return Status;
	// Allocate memory.
	Status = BS->AllocatePool(EfiBootServicesData, BufferSize, &LocalInfo);
	if (Status != EFI_SUCCESS) return Status;
	// Get the file info, free the memory on fail.
	Status = File->GetInfo(File, (EFI_GUID*) &EfiFileInfoGuid, &BufferSize, LocalInfo);
	if (Status != EFI_SUCCESS) {
		BS->FreePool(LocalInfo);
		return Status;
	}
	// Return to caller.
	*FileInfo = LocalInfo;
	return EFI_SUCCESS;
}

_Success_(return == EFI_SUCCESS) static EFI_STATUS ReadFile(__in EFI_BOOT_SERVICES* BS, __in EFI_FILE_PROTOCOL* File, __out void** Buffer, __out UINTN* Length) {
	// Get the file size from the file info.
	EFI_FILE_INFO* FileInfo;
	EFI_STATUS Status = GetFileInfo(BS, File, &FileInfo);
	if (Status != EFI_SUCCESS) {
		g_ConOut->OutputString(g_ConOut, L"GetFileInfo failed\r\n");
		return Status;
	}
	UINT64 Size64 = FileInfo->FileSize;

	// Free the file info now the required information has been obtained.
	BS->FreePool(FileInfo);

	// Check that the file size fits in a pointer-sized integer.
	if (sizeof(UINTN) < sizeof(Size64)) {
#pragma warning(push)
// Bit-shift undefined behaviour; this code will be optimised out in that case
#pragma warning(disable : 4293) 
#pragma warning(disable : 26452)
		const UINT64 MaximumPointerSizeValue = (1ull << (sizeof(UINTN) * 8)) - 1;
#pragma warning(pop)
		if (Size64 > MaximumPointerSizeValue) return EFI_BAD_BUFFER_SIZE;
	}

	UINTN Size = (UINTN)Size64;

	// Allocate memory.
	void* AllocatedBuffer;
	Status = BS->AllocatePool(EfiBootServicesData, Size, &AllocatedBuffer);
	if (Status != EFI_SUCCESS) {
		g_ConOut->OutputString(g_ConOut, L"AllocatePool failed\r\n");
		return Status;
	}

	// Read the file.
	Status = File->Read(File, &Size, AllocatedBuffer);
	if (Status != EFI_SUCCESS) {
		g_ConOut->OutputString(g_ConOut, L"File->Read failed\r\n");
		// Failure, so free the allocated buffer.
		BS->FreePool(AllocatedBuffer);
		return Status;
	}

	// Done, return the buffer and length to caller.
	*Buffer = AllocatedBuffer;
	*Length = Size;
	return Status;
}

static UINTN DecodeAsn1Length(__in UINT8** pBuffer) {
	UINT8* Buffer = *pBuffer;

	UINT8 valFirst = Buffer[0];
	UINTN Length = valFirst;
	Buffer++;
	if ((valFirst & 0x80) != 0) {
		UINT8 numOctets = valFirst & ~0x80;
		if (numOctets > sizeof(UINTN)) {
			Buffer += (numOctets - sizeof(UINTN));
		}
		UINTN Length = 0;
		while (numOctets > 0) {
			numOctets--;
			Length |= ((UINTN)Buffer[0] << (numOctets * 8));
			Buffer++;
		}
	}
	*pBuffer = Buffer;
	return Length;
}

_Success_(return != NULL) _Check_return_ static UINT8* GetPolicyFromAsn1(__in UINT8* Buffer, __in UINTN Length, _Out_ UINTN* PolicyLength) {
	// Find the start of the policy, looking for the ASN1 OID "1.3.6.1.4.1.311.79.?"
	static const UINT8 Asn1OidBytes[] = {
		0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x4f
	};

	UINT8* pSlice = MemMem(Buffer, Asn1OidBytes, Length, sizeof(Asn1OidBytes));
	if (pSlice == NULL) return NULL;
	pSlice += sizeof(Asn1OidBytes) + sizeof(UINT8);
	if (pSlice[0] == 0xA0) { // CONTEXT SPECIFIC
		pSlice++;
		DecodeAsn1Length(&pSlice);
	}
	if (pSlice >= (Buffer + Length)) return NULL;

	if (pSlice[0] != 0x04) // OCTET STRING
		return NULL;
	pSlice++;
	UINTN Asn1Length = DecodeAsn1Length(&pSlice);
	// Bounds check.
	if (pSlice >= (Buffer + Length)) return NULL;
	if ((pSlice + Asn1Length) >= (Buffer + Length)) return NULL;
	*PolicyLength = Asn1Length;
	return pSlice;
}

static bool PolicyStringEqual(_In_ PSECUREBOOT_POLICY_STRING PolicyString, _In_z_ CHAR16* String) {
	UINTN i = 0;
	for (; i < PolicyString->Length / sizeof(WCHAR); i++) {
		if (PolicyString->String[i] != String[i]) return false;
		if (String[i] == 0) return false;
	}
	return String[i] == 0;
}

static PSECUREBOOT_POLICY_REGISTRY_RULE PolicyFindRegistryRule(_In_ UINT8* PolicyBody, _In_ PSECUREBOOT_POLICY_REGISTRY_RULE RegistryRules, _In_ UINT16 RegistryRuleCount, _In_z_ CHAR16* Key, _In_z_ CHAR16* Value) {
	PSECUREBOOT_POLICY_REGISTRY_RULE This;
	for (UINTN i = 0; i < RegistryRuleCount; i++) {
		This = &RegistryRules[i];
		if (This->RootKey != HKEY_SECUREBOOT_POLICY_ROOT) continue;
		if (!PolicyStringEqual((PSECUREBOOT_POLICY_STRING)(PolicyBody + This->SubkeyNameOffset), Key)) continue;
		if (!PolicyStringEqual((PSECUREBOOT_POLICY_STRING)(PolicyBody + This->ValueNameOffset), Value)) continue;
		return This;
	}
	return NULL;
}

_Success_(return) static bool GetDeviceIdFromPolicy(_In_ UINT8 * Buffer, _In_ UINTN Length, _Out_ UINT64 * DeviceID) {
	PSECUREBOOT_POLICY_HEADER PolicyHeader = (PSECUREBOOT_POLICY_HEADER)Buffer;
	if (PolicyHeader->FormatVersion > SECUREBOOT_POLICY_MAX_VERSION) return false;

	PSECUREBOOT_POLICY_NECK PolicyNeck = (PSECUREBOOT_POLICY_NECK)((EFI_GUID*)(PolicyHeader + 1) + PolicyHeader->CanUpdateCount);
	PSECUREBOOT_POLICY_BCD_RULE BcdRules = (PSECUREBOOT_POLICY_BCD_RULE)(PolicyNeck + 1);
	PSECUREBOOT_POLICY_REGISTRY_RULE RegistryRules = (PSECUREBOOT_POLICY_REGISTRY_RULE)(BcdRules + PolicyNeck->BcdRulesCount);
	UINT8* PolicyBody = (UINT8*)(RegistryRules + PolicyNeck->RegistryRulesCount);

	PSECUREBOOT_POLICY_REGISTRY_RULE DeviceIDEntry = PolicyFindRegistryRule(PolicyBody, RegistryRules, PolicyNeck->RegistryRulesCount, L"Debug", L"DeviceID");
	if (DeviceIDEntry == NULL) return false;

	PSECUREBOOT_POLICY_VALUE_QWORD DeviceIDValue = (PSECUREBOOT_POLICY_VALUE_QWORD)(PolicyBody + DeviceIDEntry->ValueOffset);
	if (DeviceIDValue->Header.Flags.Type != SECUREBOOT_POLICY_VALUE_TYPE_QWORD) return false;
	*DeviceID = DeviceIDValue->Value;
	return true;
}

EFI_STATUS EfiMain(__in EFI_HANDLE ImageHandle, __in EFI_SYSTEM_TABLE* SystemTable) {
	EFI_STATUS Status = EFI_SUCCESS;
	EFI_BOOT_SERVICES* BS = SystemTable->BootServices;
	EFI_RUNTIME_SERVICES* RT = SystemTable->RuntimeServices;
	g_ConOut = SystemTable->ConOut;
	// Get LOADED_IMAGE_PROTOCOL
	EFI_LOADED_IMAGE_PROTOCOL* LoadedImage;
	Status = BS->HandleProtocol(ImageHandle, (EFI_GUID*) &EfiLoadedImageProtocolGuid, &LoadedImage);
	if (Status != EFI_SUCCESS) return Status;
	// Open the FS for the loaded image.
	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* ImagePartition;
	Status = BS->OpenProtocol(LoadedImage->DeviceHandle, (EFI_GUID*)&EfiFileSystemProtocolGuid, &ImagePartition, ImageHandle, NULL, EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
	if (Status != EFI_SUCCESS) return Status;
	// Open the volume.
	EFI_FILE_PROTOCOL* VolumeRoot;
	Status = ImagePartition->OpenVolume(ImagePartition, &VolumeRoot);
	if (Status != EFI_SUCCESS) return Status;
	do {
		// Open the file.
		EFI_FILE_PROTOCOL* VolumeFile;
		Status = TryOpenPolicy(&VolumeFile, VolumeRoot, LoadedImage);
		if (Status != EFI_SUCCESS) break;
		do {
			// Read the entire file.
			UINT8* PolicyFileData;
			UINTN PolicyFileSize;
			Status = ReadFile(BS, VolumeFile, &PolicyFileData, &PolicyFileSize);
			if (Status != EFI_SUCCESS) break;
			do {
				// Obtain the policy data from the ASN.1 blob.
				UINTN PolicySize;
				UINT8* PolicyData = GetPolicyFromAsn1(PolicyFileData, PolicyFileSize, &PolicySize);
				if (PolicyData == NULL) {
					SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Could not get the unsigned policy from the ASN1 signed blob\r\n");
					Status = EFI_UNSUPPORTED;
					break;
				}
				// Get the DeviceID from the policy.
				UINT64 DeviceID;
				if (!GetDeviceIdFromPolicy(PolicyData, PolicySize, &DeviceID)) {
					SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Could not find any DeviceID in the policy\r\n");
					Status = EFI_UNSUPPORTED;
					break;
				}
				// Set the DeviceID variable.
				Status = RT->SetVariable(L"CopyOfDeviceID", (EFI_GUID*)&EfiMicrosoftVendorGuid, EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_NON_VOLATILE, sizeof(DeviceID), &DeviceID);
				if (Status != EFI_SUCCESS) {
					SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Could not set DeviceID\r\n");
					break;
				}
				SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Set DeviceID\r\n");
				// Set the CurrentPolicy and CurrentActivePolicy variables.
				// CurrentPolicy may fail, so don't check the result there.
				RT->SetVariable(L"CurrentPolicy", (EFI_GUID*)&EfiMicrosoftVendorGuid, EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_NON_VOLATILE, PolicyFileSize, PolicyFileData);
				Status = RT->SetVariable(L"CurrentActivePolicy", (EFI_GUID*)&EfiMicrosoftVendorGuid, EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_NON_VOLATILE, PolicyFileSize, PolicyFileData);
				if (Status != EFI_SUCCESS) break;
				SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Installed policy\r\n");
			} while (false);
			// Free the policy file data.
			BS->FreePool(PolicyFileData);
		} while (false);
		VolumeFile->Close(VolumeFile);
	} while (false);
	VolumeRoot->Close(VolumeRoot);

	{
		SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Press any key to exit...\r\n");
		EFI_STATUS KeyStatus = EFI_NOT_READY;
		do {
			UINTN EventIndex;
			BS->WaitForEvent(1, SystemTable->ConIn->WaitForKey, &EventIndex);
			EFI_KEY_DATA Key;
			KeyStatus = SystemTable->ConIn->ReadKeyStroke(SystemTable->ConIn, &Key);
		} while (KeyStatus == EFI_NOT_READY);
	}

	return Status;
}