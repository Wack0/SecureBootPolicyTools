using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SecureBootPolicy.Binary
{
	/*
	 * File layout on disk:
	 * Header
	 * Header.CanUpdateCount * GUID
	 * Flags
	 * Flags.BcdRulesCount * BcdRule
	 * Flags.RegistryRulesCount * RegistryRule
	 * Body, all offsets are into this
	 */
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	struct Header
	{
		public ushort FormatVersion;
		public uint PolicyVersion;
		public Guid PolicyPublisher;
		public ushort CanUpdateCount;
	}
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	struct Flags
	{
		public uint OptionFlags;
		public ushort BcdRulesCount;
		public ushort RegistryRulesCount;
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	struct BcdRule
	{
		public uint ObjectType;
		public uint Element;
		public uint ValueOffset;
	}
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	struct RegistryRule
	{
		public uint RootKey;
		public uint SubkeyNameOffset;
		public uint ValueNameOffset;
		public uint ValueOffset;
	}
}
