// Secure Boot Policy definitions.
#pragma once
#include "efi.h"

/*
	Structure of an on-disk secure boot policy:
	SECUREBOOT_POLICY_HEADER Header;
	GUID CanUpdate[Header.CanUpdateCount];
	SECUREBOOT_POLICY_NECK Neck;
	SECUREBOOT_POLICY_BCD_RULE BcdRules[Neck.BcdRulesCount];
	SECUREBOOT_POLICY_REGISTRY_RULE RegistryRules[Neck.RegistryRulesCount];
	BYTE Body[...]; // all offsets in substructures/etc are from the body
*/
#pragma pack(push, 1)
typedef struct _SECUREBOOT_POLICY_HEADER {
	UINT16 FormatVersion;
	UINT32 PolicyVersion;
	EFI_GUID PolicyPublisher;
	UINT16 CanUpdateCount;
} SECUREBOOT_POLICY_HEADER, *PSECUREBOOT_POLICY_HEADER;

typedef struct _SECUREBOOT_POLICY_NECK {
	UINT32 OptionFlags;
	UINT16 BcdRulesCount;
	UINT16 RegistryRulesCount;
} SECUREBOOT_POLICY_NECK, *PSECUREBOOT_POLICY_NECK;

typedef struct _SECUREBOOT_POLICY_BCD_RULE {
	UINT32 ObjectType;
	UINT32 Element;
	UINT32 ValueOffset;
} SECUREBOOT_POLICY_BCD_RULE, *PSECUREBOOT_POLICY_BCD_RULE;

typedef struct _SECUREBOOT_POLICY_REGISTRY_RULE {
	UINT32 RootKey;
	UINT32 SubkeyNameOffset;
	UINT32 ValueNameOffset;
	UINT32 ValueOffset;
} SECUREBOOT_POLICY_REGISTRY_RULE, *PSECUREBOOT_POLICY_REGISTRY_RULE;

typedef struct _SECUREBOOT_POLICY_VALUE_HEADER {
	union {
		UINT16 Raw;
		struct {
			UINT16 Type : 5;
			UINT16 ForFveTpm : 1;
			UINT16 ForVbs : 1;
		};
	} Flags;
} SECUREBOOT_POLICY_VALUE_HEADER, *PSECUREBOOT_POLICY_VALUE_HEADER;

typedef struct _SECUREBOOT_POLICY_STRING {
	UINT16 Length;
	CHAR16 String[1];
} SECUREBOOT_POLICY_STRING, *PSECUREBOOT_POLICY_STRING;

typedef struct _SECUREBOOT_POLICY_VALUE_QWORD {
	SECUREBOOT_POLICY_VALUE_HEADER Header;
	UINT64 Value;
} SECUREBOOT_POLICY_VALUE_QWORD, *PSECUREBOOT_POLICY_VALUE_QWORD;

#pragma pack(pop)

#define SECUREBOOT_POLICY_MAX_VERSION 2 // 3 and above is for SiPolicies. Nice work as usual MS.
#define HKEY_SECUREBOOT_POLICY_ROOT 0x81000000
#define SECUREBOOT_POLICY_VALUE_TYPE_QWORD 5