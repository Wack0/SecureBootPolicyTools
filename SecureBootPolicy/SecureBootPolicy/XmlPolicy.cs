using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Schema;
using System.Xml.Serialization;

namespace SecureBootPolicy
{
	public class XmlPolicy
	{
		private static Guid s_DebugPublisher = new Guid(0x0CDAD82E, 0xD839, 0x4754, 0x89, 0xA1, 0x84, 0x4A, 0xB2, 0x82, 0x31, 0x2B);
		private static Guid s_PreProdPublisher = new Guid(0xA3254FA8, 0xDB95, 0x488F, 0xA2, 0x99, 0x1C, 0xB0, 0x01, 0xE5, 0xA3, 0xF2);
		private static HashSet<byte> s_ValidScenarios = new HashSet<byte>()
		{
			Constants.ID_SIGNINGSCENARIO_BOOT_APPS,
			Constants.ID_SIGNINGSCENARIO_WINDOWS,
			Constants.ID_SIGNINGSCENARIO_HAL_EXTENSIONS,
			Constants.ID_SIGNINGSCENARIO_ELAM_DRIVERS,
			Constants.ID_SIGNINGSCENARIO_DRIVERS,
			Constants.ID_SIGNINGSCENARIO_BOOT_REVOCATION_LIST,
			Constants.ID_SIGNINGSCENARIO_FIRMWARE_UPDATE,
			Constants.ID_SIGNINGSCENARIO_CORE_EXTENSIONS,
			Constants.ID_SIGNINGSCENARIO_PLATFORM_MANIFEST_REQUIRED,
			Constants.ID_SIGNINGSCENARIO_RUNTIME_REVOCATION_LIST,
			Constants.ID_SIGNINGSCENARIO_PLATFORM_MANIFEST,
			Constants.ID_SIGNINGSCENARIO_FLASHING,

			// ci.dll scenarios
			Constants.ID_SIGNINGSCENARIO_ENTERPRISE,
			Constants.ID_SIGNINGSCENARIO_CUSTOM1,
			Constants.ID_SIGNINGSCENARIO_AUTHENTICODE,
			Constants.ID_SIGNINGSCENARIO_CUSTOM2,
			Constants.ID_SIGNINGSCENARIO_STORE,
			Constants.ID_SIGNINGSCENARIO_ANTIMALWARE,
			Constants.ID_SIGNINGSCENARIO_MICROSOFT,
			Constants.ID_SIGNINGSCENARIO_CUSTOM4,
			Constants.ID_SIGNINGSCENARIO_CUSTOM5,
			Constants.ID_SIGNINGSCENARIO_DYNAMIC_CODEGEN,
			Constants.ID_SIGNINGSCENARIO_CUSTOM7,
			Constants.ID_SIGNINGSCENARIO_WINDOWS_TCB,
			Constants.ID_SIGNINGSCENARIO_CUSTOM6,
			Constants.ID_SIGNINGSCENARIO_DRM
		};
		private static Dictionary<HashAlgorithmType, ushort> s_HashAlgorithmToCalg = new Dictionary<HashAlgorithmType, ushort>()
		{
			{ HashAlgorithmType.MD5, 0x8003 },
			{ HashAlgorithmType.SHA1, 0x8004 },
			{ HashAlgorithmType.SHA256, 0x800C },
			{ HashAlgorithmType.SHA384, 0x800D },
			{ HashAlgorithmType.SHA512, 0x800E }
		};
		private static Dictionary<string, uint> s_BcdFriendlyNameToID_Any = new Dictionary<string, uint>()
		{
			// library
			{ "device", 0x11000001 },
			{ "path", 0x12000002 },
			{ "description", 0x12000004 },
			{ "locale", 0x12000005 },
			{ "inherit", 0x14000006 },
			{ "truncatememory", 0x15000007 },
			{ "recoverysequence", 0x14000008 },
			{ "recoveryenabled", 0x16000009 },
			{ "badmemorylist", 0x1700000A },
			{ "badmemoryaccess", 0x1600000B },
			{ "firstmegabytepolicy", 0x1500000C },
			{ "relocatephysical", 0x1500000D },
			{ "avoidlowmemory", 0x1500000E },
			{ "traditionalkseg", 0x1600000F },
			{ "bootdebug", 0x16000010 },
			{ "debugtype", 0x15000011 },
			{ "debugaddress", 0x15000012 },
			{ "debugport", 0x15000013 },
			{ "baudrate", 0x15000014 },
			{ "channel", 0x15000015 },
			{ "targetname", 0x12000016 },
			{ "noumex", 0x16000017 },
			{ "debugstart", 0x15000018 },
			{ "busparams", 0x12000019 },
			{ "hostip", 0x1500001A },
			{ "port", 0x1500001B },
			{ "dhcp", 0x1600001C },
			{ "key", 0x1200001D },
			{ "vm", 0x1600001E },
			{ "hostipv6", 0x1200001F },
			{ "bootems", 0x16000020 },
			{ "emsport", 0x15000022 },
			{ "emsbaudrate", 0x15000023 },
			{ "loadoptions", 0x12000030 },
			{ "attemptnonbcdstart", 0x16000031 },
			{ "advancedoptions", 0x16000040 },
			{ "optionsedit", 0x16000041 },
			{ "keyringaddress", 0x15000042 },
			{ "bootstatdevice", 0x11000043 },
			{ "bootstatfilepath", 0x12000044 },
			{ "preservebootstat", 0x16000045 },
			{ "graphicsmodedisabled", 0x16000046 },
			{ "configaccesspolicy", 0x15000047 },
			{ "nointegritychecks", 0x16000048 },
			{ "testsigning", 0x16000049 },
			{ "fontpath", 0x1200004A },
			{ "integrityservices", 0x1500004B },
			{ "volumebandid", 0x1500004C },
			{ "extendedinput", 0x16000050 },
			{ "initialconsoleinput", 0x15000051 },
			{ "graphicsresolution", 0x15000052 },
			{ "restartonfailure", 0x16000053 },
			{ "highestmode", 0x16000054 },
			{ "isolatedcontext", 0x16000060 },
			{ "displaymessage", 0x15000065 },
			{ "displaymessageoverride", 0x15000066 },
			{ "nobootuxlogo", 0x16000067 },
			{ "nobootuxtext", 0x16000068 },
			{ "nobootuxprogress", 0x16000069 },
			{ "nobootuxfade", 0x1600006A },
			{ "bootuxreservepooldebug", 0x1600006B },
			{ "bootuxdisabled", 0x1600006C },
			{ "bootuxfadeframes", 0x1500006D },
			{ "bootuxdumpstats", 0x1600006E },
			{ "bootuxshowstats", 0x1600006F },
			{ "multibootsystem", 0x16000071 },
			{ "nokeyboard", 0x16000072 },
			{ "aliaswindowskey", 0x15000073 },
			{ "bootshutdowndisabled", 0x16000074 },
			{ "performancefrequency", 0x15000075 },
			{ "securebootrawpolicy", 0x15000076 },
			{ "allowedinmemorysettings", 0x17000077 },
			{ "bootuxpreallocprogress", 0x16000078 },
			{ "bootuxtransitiontime", 0x15000079 },
			{ "mobilegraphics", 0x1600007A },
			{ "forcefipscrypto", 0x1600007B },
			{ "booterrorux", 0x1500007D },
			{ "flightsigning", 0x1600007E },
			{ "measuredbootlogformat", 0x1500007F },
			{ "displayrotation", 0x15000080 },
			{ "logcontrol", 0x15000081 },
			{ "nofirmwaresync", 0x16000082 },
			{ "recoveryosdevice", 0x11000083 },
			{ "windowssyspart", 0x11000084 },
			{ "enableuwfbootfilter", 0x16000085 },
			{ "enabletxtmle", 0x15000086 },
			{ "numlock", 0x16000087 },
			{ "additionalcipolicy", 0x12000088 },
			{ "linearaddress57", 0x15000088 },

			// ffuloader/charge
			{ "skipffumode", 0x26000202 },
			{ "forceffumode", 0x26000203 },
			{ "chargethreshold", 0x25000510 },
			{ "offmodecharging", 0x26000512 },
			{ "bootflow", 0x25000AAA },

			// template
			{ "devicetype", 0x45000001 },
			{ "applicationrelativepath", 0x42000002 },
			{ "ramdiskdevicerelativepath", 0x42000003 },
			{ "omitosloaderelements", 0x46000004 },
			{ "elementstomigrate", 0x47000006 },
			{ "recoveryos", 0x46000010 },

			// device
			{ "ramdiskimageoffset", 0x35000001 },
			{ "ramdisktftpclientport", 0x35000002 },
			{ "ramdisksdidevice", 0x31000003 },
			{ "ramdisksdipath", 0x32000004 },
			{ "ramdiskimagelength", 0x35000005 },
			{ "exportascd", 0x36000006 },
			{ "ramdisktftpblocksize", 0x35000007 },
			{ "ramdisktftpwindowsize", 0x35000008 },
			{ "ramdiskmcenabled", 0x36000009 },
			{ "ramdiskmctftpfallback", 0x3600000A },
			{ "ramdisktftpvarwindow", 0x3600000B },
			{ "vhdramdiskboot", 0x3600000C },
			{ "vhdramdisklength", 0x3500000D },

			// legacyldr
			{ "bpbstring", 0x22000001 },

			// startup
			{ "pxesoftreboot", 0x26000001 },
			{ "applicationname", 0x22000002 },

			// mobilestartup
			{ "enablebootdebugpolicy", 0x26000145 },
			{ "enablebootorderclean", 0x26000146 },
			{ "enabledeviceid", 0x26000147 },
			{ "enableffuloader", 0x26000148 },
			{ "enableiuloader", 0x26000149 },
			{ "enablemassstorage", 0x2600014A },
			{ "enablerpmbprovisioning", 0x2600014B },
			{ "enablesecurebootpolicy", 0x2600014C },
			{ "enablestartcharge", 0x2600014D },
			{ "enableresettpm", 0x2600014E },
		};

		private static Dictionary<string, uint> s_BcdFriendlyNameToID_Bootmgr = new Dictionary<string, uint>()
		{
			{ "displayorder", 0x24000001 },
			{ "bootsequence", 0x24000002 },
			{ "default", 0x23000003 },
			{ "timeout", 0x25000004 },
			{ "resume", 0x26000005 },
			{ "resumeobject", 0x23000006 },
			{ "startupsequence", 0x24000007 },
			{ "toolsdisplayorder", 0x24000010 },
			{ "displaybootmenu", 0x26000020 },
			{ "noerrordisplay", 0x26000021 },
			{ "bcddevice", 0x21000022 },
			{ "bcdfilepath", 0x22000023 },
			{ "hormenabled", 0x26000024 },
			{ "hiberboot", 0x26000025 },
			{ "passwordoverride", 0x22000026 },
			{ "pinpassphraseoverride", 0x22000027 },
			{ "processcustomactionsfirst", 0x26000028 },
			{ "enabledummylogentry", 0x2600002A },
			{ "customactions", 0x27000030 },
			{ "persistbootsequence", 0x26000031 },
			{ "skipstartupsequence", 0x26000032 },
			{ "fverecoveryurl", 0x22000040 },
			{ "fverecoverymessage", 0x22000041 },
			{ "flightedbootmgr", 0x26000042 },
			{ "fveunlockretryipv4", 0x25000043 },
			{ "fveunlockretryipv6", 0x25000044 },
			{ "fveserveraddressipv4", 0x22000045 },
			{ "fveserveraddressipv6", 0x22000046 },
			{ "fveipaddressipv4", 0x22000047 },
			{ "fveipaddressipv6", 0x22000048 },
			{ "fvesubnetmaskipv4", 0x22000049 },
			{ "fveaddressprefixipv6", 0x2200004A },
			{ "fvegatewayipv4", 0x2200004B },
			{ "fvegatewayipv6", 0x2200004C },
			{ "fvenetworktimeout", 0x2500004D },
			{ "fveremoteportipv4", 0x2500004E },
			{ "fveremoteportipv6", 0x2500004F },
			{ "fvestationportipv4", 0x25000050 },
			{ "fvestationportipv6", 0x25000051 },
		};

		private static Dictionary<string, uint> s_BcdFriendlyNameToID_OsLoader = new Dictionary<string, uint>()
		{
			{ "osdevice", 0x21000001 },
			{ "systemroot", 0x22000002 },
			{ "resumeobject", 0x23000003 },
			{ "stampdisks", 0x26000004 },
			{ "fveunlockdevice", 0x21000005 },
			{ "detecthal", 0x26000010 },
			{ "kernel", 0x22000011 },
			{ "hal", 0x22000012 },
			{ "dbgtransport", 0x22000013 },
			{ "nx", 0x25000020 },
			{ "pae", 0x25000021 },
			{ "winpe", 0x26000022 },
			{ "nocrashautoreboot", 0x26000024 },
			{ "lastknowngood", 0x26000025 },
			{ "oslnointegritychecks", 0x26000026 },
			{ "osltestsigning", 0x26000027 },
			{ "nolowmem", 0x26000030 },
			{ "removememory", 0x25000031 },
			{ "increaseuserva", 0x25000032 },
			{ "perfmem", 0x25000033 },
			{ "vga", 0x26000040 },
			{ "quietboot", 0x26000041 },
			{ "novesa", 0x26000042 },
			{ "novga", 0x26000043 },
			{ "clustermodeaddressing", 0x25000050 },
			{ "usephysicaldestination", 0x26000051 },
			{ "restrictapiccluster", 0x25000052 },
			{ "evstore", 0x22000053 },
			{ "uselegacyapicmode", 0x26000054 },
			{ "x2apicpolicy", 0x25000055 },
			{ "onecpu", 0x26000060 },
			{ "numproc", 0x25000061 },
			{ "maxproc", 0x26000062 },
			{ "configflags", 0x25000063 },
			{ "maxgroup", 0x26000064 },
			{ "groupaware", 0x26000065 },
			{ "groupsize", 0x25000066 },
			{ "usefirmwarepcisettings", 0x26000070 },
			{ "msi", 0x25000071 },
			{ "pciexpress", 0x25000072 },
			{ "safeboot", 0x25000080 },
			{ "safebootalternateshell", 0x26000081 },
			{ "bootlog", 0x26000090 },
			{ "sos", 0x26000091 },
			{ "debug", 0x260000A0 },
			{ "halbreakpoint", 0x260000A1 },
			{ "useplatformclock", 0x260000A2 },
			{ "forcelegacyplatform", 0x260000A3 },
			{ "useplatformtick", 0x260000A4 },
			{ "disabledynamictick", 0x260000A5 },
			{ "tscsyncpolicy", 0x250000A6 },
			{ "ems", 0x260000B0 },
			{ "forcefailure", 0x250000C0 },
			{ "driverloadfailurepolicy", 0x250000C1 },
			{ "bootmenupolicy", 0x250000C2 },
			{ "onetimeadvancedoptions", 0x260000C3 },
			{ "onetimeoptionsedit", 0x260000C4 },
			{ "bootstatuspolicy", 0x250000E0 },
			{ "disableelamdrivers", 0x260000E1 },
			{ "hypervisorlaunchtype", 0x250000F0 },
			{ "hypervisorpath", 0x220000F1 },
			{ "hypervisordebug", 0x260000F2 },
			{ "hypervisordebugtype", 0x250000F3 },
			{ "hypervisordebugport", 0x250000F4 },
			{ "hypervisorbaudrate", 0x250000F5 },
			{ "hypervisorchannel", 0x250000F6 },
			{ "bootux", 0x250000F7 },
			{ "hypervisordisableslat", 0x260000F8 },
			{ "hypervisorbusparams", 0x220000F9 },
			{ "hypervisornumproc", 0x250000FA },
			{ "hypervisorrootprocpernode", 0x250000FB },
			{ "hypervisoruselargevtlb", 0x260000FC },
			{ "hypervisorhostip", 0x250000FD },
			{ "hypervisorhostport", 0x250000FE },
			{ "hypervisordebugpages", 0x250000FF },
			{ "tpmbootentropy", 0x25000100 },
			{ "hypervisorusekey", 0x22000110 },
			{ "hypervisorproductskutype", 0x22000112 },
			{ "hypervisorrootproc", 0x25000113 },
			{ "hypervisordhcp", 0x26000114 },
			{ "hypervisoriommupolicy", 0x25000115 },
			{ "hypervisorusevapic", 0x26000116 },
			{ "hypervisorloadoptions", 0x22000117 },
			{ "hypervisormsrfilterpolicy", 0x25000118 },
			{ "hypervisormmionxpolicy", 0x25000119 },
			{ "hypervisorschedulertype", 0x2500011A },
			{ "hypervisorrootprocnumanodes", 0x2200011B },
			{ "hypervisorperfmon", 0x2500011C },
			{ "hypervisorrootprocpercore", 0x2500011D },
			{ "hypervisorrootprocnumanodelps", 0x2200011E },
			{ "xsavepolicy", 0x25000120 },
			{ "xsaveaddfeature0", 0x25000121 },
			{ "xsaveaddfeature1", 0x25000122 },
			{ "xsaveaddfeature2", 0x25000123 },
			{ "xsaveaddfeature3", 0x25000124 },
			{ "xsaveaddfeature4", 0x25000125 },
			{ "xsaveaddfeature5", 0x25000126 },
			{ "xsaveaddfeature6", 0x25000127 },
			{ "xsaveaddfeature7", 0x25000128 },
			{ "xsaveremovefeature", 0x25000129 },
			{ "xsaveprocessorsmask", 0x2500012A },
			{ "xsavedisable", 0x2500012B },
			{ "kerneldebugtype", 0x2500012C },
			{ "kernelbusparams", 0x2200012D },
			{ "kerneldebugaddress", 0x2500012E },
			{ "kerneldebugport", 0x2500012F },
			{ "claimedtpmcounter", 0x25000130 },
			{ "kernelchannel", 0x25000131 },
			{ "kerneltargetname", 0x22000132 },
			{ "kernelhostip", 0x25000133 },
			{ "kernelport", 0x25000134 },
			{ "kerneldhcp", 0x26000135 },
			{ "kernelkey", 0x22000136 },
			{ "imchivename", 0x22000137 },
			{ "imcdevice", 0x21000138 },
			{ "kernelbaudrate", 0x25000139 },
			{ "mfgmode", 0x22000140 },
			{ "event", 0x26000141 },
			{ "vsmlaunchtype", 0x25000142 },
			{ "hypervisorenforcedcodeintegrity", 0x25000144 },
			{ "dtrace", 0x26000145 },
			{ "systemdatadevice", 0x21000150 },
			{ "osarcdevice", 0x21000151 },
			{ "capsuledumpdevice", 0x21000152 },
			{ "osdatadevice", 0x21000153 },
			{ "bspdevice", 0x21000154 },
			{ "bspfilepath", 0x21000155 },
			{ "kernelhostipv6", 0x22000156 },
			{ "hypervisorhostipv6", 0x22000161 },
		};

		private static Dictionary<string, uint> s_BcdFriendlyNameToID_Resume = new Dictionary<string, uint>()
		{
			{ "filedevice", 0x21000001 },
			{ "filepath", 0x22000002 },
			{ "customsettings", 0x26000003 },
			{ "pae", 0x26000004 },
			{ "associatedosdevice", 0x21000005 },
			{ "debugoptionenabled", 0x26000006 },
			{ "bootux", 0x25000007 },
			{ "bootmenupolicy", 0x25000008 },
			{ "hormenabled", 0x26000024 },
		};

		private static Dictionary<string, uint> s_BcdFriendlyNameToID_Memdiag = new Dictionary<string, uint>()
		{
			{ "passcount", 0x25000001 },
			{ "testmix", 0x25000002 },
			{ "failurecount", 0x25000003 },
			{ "cacheenable", 0x26000003 },
			{ "testtofail", 0x25000004 },
			{ "failuresenabled", 0x26000004 },
			{ "stridefailcount", 0x25000005 },
			{ "invcfailcount", 0x25000006 },
			{ "matsfailcount", 0x25000007 },
			{ "randfailcount", 0x25000008 },
			{ "chckrfailcount", 0x25000009 },
		};

		private SbPolicy m_Policy;
		private string m_PolicyPath;
		private string m_ValidationError;
		private bool m_IsValid;
		public XmlPolicy(string xmlPath)
		{
			if (!File.Exists(xmlPath)) throw new FileNotFoundException();
			m_PolicyPath = xmlPath;
			m_IsValid = true;
			ValidateXmlFile();
		}

		private void ValidateXmlFile()
		{
			XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
			XmlReader xmlReader = null;
			xmlReaderSettings.XmlResolver = null;
			try
			{
				XmlReader xmlReader2 = XmlReader.Create(Properties.Resources.SBPolicy, xmlReaderSettings);
				XmlSchema schema;
				try
				{
					schema = XmlSchema.Read(xmlReader2, null);
				}
				finally
				{
					xmlReader2.Close();
				}
				XmlSchemaSet xmlSchemaSet = new XmlSchemaSet();
				xmlSchemaSet.Add(schema);
				xmlReaderSettings.ValidationType = ValidationType.Schema;
				xmlReaderSettings.Schemas = xmlSchemaSet;
				xmlReaderSettings.ValidationEventHandler += this.ValidateXmlFileCallback;
				xmlReader = XmlReader.Create(new XmlTextReader(m_PolicyPath), xmlReaderSettings);
				XmlSerializer xmlSerializer = new XmlSerializer(typeof(SbPolicy));
				m_Policy = (SbPolicy)xmlSerializer.Deserialize(xmlReader);
				// Replace any null arrays with zero-length ones.
				if (m_Policy.BcdRules == null) m_Policy.BcdRules = new BcdRule[0];
				if (m_Policy.CiSigners == null) m_Policy.CiSigners = new CiSigner[0];
				if (m_Policy.EKUs == null) m_Policy.EKUs = new EKU[0];
				if (m_Policy.Rules == null) m_Policy.Rules = new RuleType[0];
				if (m_Policy.Settings == null) m_Policy.Settings = new Setting[0];
				if (m_Policy.Signers == null) m_Policy.Signers = new Signer[0];
				if (m_Policy.SigningScenarios == null) m_Policy.SigningScenarios = new SigningScenario[0];
			}
			finally
			{
				if (xmlReader != null)
				{
					xmlReader.Close();
				}
			}
			if (!m_IsValid)
			{
				throw new InvalidDataException(m_ValidationError);
			}
		}

		private void ValidateXmlFileCallback(object sender, ValidationEventArgs args)
		{
			m_IsValid = false;
			m_ValidationError = args.Message;
		}

		public void ConvertToBinaryFile(string binaryFilePath)
        {
			using (var fs = File.Open(binaryFilePath, FileMode.Create))
				ConvertToBinary(fs);
        }

		public void ConvertToBinary(Stream stream)
        {
			var msBody = new MemoryStream();
			var bwBody = new BinaryWriter(msBody, Encoding.Unicode, true);

			var header = default(Binary.Header);
			header.FormatVersion = 2;
			header.PolicyVersion = !m_Policy.PolicyVersionSpecified ? 1 : m_Policy.PolicyVersion;
			switch (m_Policy.PolicyPublisher)
            {
				case PolicyPublisherType.Debug:
					header.PolicyPublisher = s_DebugPublisher;
					break;
				case PolicyPublisherType.PreProduction:
					header.PolicyPublisher = s_PreProdPublisher;
					break;
				default:
					throw new InvalidDataException();
            }
			// I don't think anything ever actually uses this?
			header.CanUpdateCount = 0;


			stream.Write(SpanExtensions.AsSpan(ref header));
			// if there were any canupdate GUIDs, they would be written out here.

			var flags = default(Binary.Flags);
			flags.OptionFlags = ConvertFlags();
			flags.BcdRulesCount = (ushort) m_Policy.BcdRules.Length;

			var registry = CreateRegistry();
			if (registry.Count > ushort.MaxValue) throw new InvalidDataException("There can only be a maximum of 65535 registry entries. Each CI signer uses 1-3, each CI signing scenario uses 3-4.");
			flags.RegistryRulesCount = (ushort) registry.Count;
			stream.Write(SpanExtensions.AsSpan(ref flags));

			// Serialise the BCD rules.
			foreach (var bcd in m_Policy.BcdRules)
            {
				var bcdHdr = default(Binary.BcdRule);
				Dictionary<string, uint> dictToUse = null;
				switch (bcd.Object)
                {
					case BcdObjectType.Any:
						bcdHdr.ObjectType = 0;
						dictToUse = s_BcdFriendlyNameToID_Bootmgr;
						break;
					case BcdObjectType.bootmgr:
						bcdHdr.ObjectType = 0x10100002;
						dictToUse = s_BcdFriendlyNameToID_Bootmgr;
						break;
					case BcdObjectType.osloader:
						bcdHdr.ObjectType = 0x10200003;
						dictToUse = s_BcdFriendlyNameToID_OsLoader;
						break;
					case BcdObjectType.resume:
						bcdHdr.ObjectType = 0x10200004;
						dictToUse = s_BcdFriendlyNameToID_Resume;
						break;
					case BcdObjectType.memdiag:
						bcdHdr.ObjectType = 0x10200005;
						dictToUse = s_BcdFriendlyNameToID_Memdiag;
						break;
					case BcdObjectType.ntldr:
						bcdHdr.ObjectType = 0x10300006;
						dictToUse = s_BcdFriendlyNameToID_Bootmgr;
						break;
				}

				var friendlyName = bcd.Element.ToLower();
				if (friendlyName.StartsWith("custom:"))
                {
					bcdHdr.Element = uint.Parse(friendlyName.Substring(7), System.Globalization.NumberStyles.HexNumber);
                } else
                {
					if (!s_BcdFriendlyNameToID_Any.TryGetValue(friendlyName, out bcdHdr.Element) && !dictToUse.TryGetValue(friendlyName, out bcdHdr.Element))
						throw new InvalidDataException(string.Format("Unknown BCD element friendly name '{0}', perhaps use custom:HEX_ELEMENT instead", friendlyName));
                }
				if (msBody.Position > uint.MaxValue) throw new InvalidOperationException("Secure Boot policy body can not be larger than 4GB.");
				bcdHdr.ValueOffset = (uint) msBody.Position;
				WriteValue(bwBody, bcd.Value, bcd.RequiresBitLockerWithTPMSpecified && bcd.RequiresBitLockerWithTPM, bcd.RequiresVBSSpecified && bcd.RequiresVBS);
				stream.Write(SpanExtensions.AsSpan(ref bcdHdr));
            }

			// Serialise the registry.
			foreach (var entry in registry)
            {
				var regHdr = default(Binary.RegistryRule);
				regHdr.RootKey = Constants.HKEY_SECUREBOOT_POLICIES_ROOT;
				if (msBody.Position > uint.MaxValue) throw new InvalidOperationException("Secure Boot policy body can not be larger than 4GB.");
				regHdr.SubkeyNameOffset = (uint)msBody.Position;
				WriteRawString(bwBody, entry.Key);
				if (msBody.Position > uint.MaxValue) throw new InvalidOperationException("Secure Boot policy body can not be larger than 4GB.");
				regHdr.ValueNameOffset = (uint)msBody.Position;
				WriteRawString(bwBody, entry.ValueName);
				if (msBody.Position > uint.MaxValue) throw new InvalidOperationException("Secure Boot policy body can not be larger than 4GB.");
				regHdr.ValueOffset = (uint)msBody.Position;
				WriteValue(bwBody, entry.Value);
				stream.Write(SpanExtensions.AsSpan(ref regHdr));
			}

			// Write out the body.
			using (bwBody) { }
			msBody.Position = 0;
			msBody.CopyTo(stream);
			stream.Flush();
        }

		private uint ConvertFlags()
        {
			uint ret = 0;
			foreach (var rule in m_Policy.Rules)
            {
				// OptionType enum is defined in bit order in the XSD.
				// XSD.EXE when converting to C# also defines the enum in bit order.
				// So, all that needs to be done is this:
				ret |= (1u << (int)rule.Item);
            }
			return ret;
        }

		private static Setting NewRegistryEntryWithoutValue(string Key, string ValueName)
        {
			return new Setting()
			{
				Key = Key,
				ValueName = ValueName
			};
        }

		private static Setting NewRegistryEntry(string Key, string ValueName, byte[] Value)
        {
			var ret = NewRegistryEntryWithoutValue(Key, ValueName);
			ret.Value = new SettingValueType() { Item = Value };
			return ret;
        }

		private static Setting NewRegistryEntry(string Key, string ValueName, bool Value)
		{
			var ret = NewRegistryEntryWithoutValue(Key, ValueName);
			ret.Value = new SettingValueType() { Item = Value };
			return ret;
		}

		private static Setting NewRegistryEntry(string Key, string ValueName, uint Value)
		{
			var ret = NewRegistryEntryWithoutValue(Key, ValueName);
			ret.Value = new SettingValueType() { Item = Value };
			return ret;
		}

		private static Setting NewRegistryEntry(string Key, string ValueName, ulong Value)
		{
			var ret = NewRegistryEntryWithoutValue(Key, ValueName);
			ret.Value = new SettingValueType() { Item = Value };
			return ret;
		}

		private static Setting NewRegistryEntry(string Key, string ValueName, uint[] Value, uint Default = default)
		{
			var ret = NewRegistryEntryWithoutValue(Key, ValueName);
			ret.Value = new SettingValueType() { Item = new DWordArrayType() { Default = Default, Values = Value }  };
			return ret;
		}

		private static Setting NewRegistryEntry(string Key, string ValueName, string Value)
		{
			var ret = NewRegistryEntryWithoutValue(Key, ValueName);
			ret.Value = new SettingValueType() { Item = Value };
			return ret;
		}

		private IList<Setting> CreateRegistry()
        {
			// bring in the stuff that isn't CI rules.
			var ret = new List<Setting>(m_Policy.Settings);

			// add the device id
			ret.Add(NewRegistryEntry(Constants.KEY_DEVICEID, Constants.VALUE_DEVICEID, m_Policy.DeviceID));

			// if there are no signing scenarios or no signers, just return the raw settings.
			// if no signers are present, custom signing policy won't be loaded;
			// if no scenarios are present (but signers are present), then the custom signing policy will disallow everything.
			if (m_Policy.SigningScenarios.Length == 0 || m_Policy.Signers.Length == 0) return ret;

			// parse EKUs into a dict
			var EKUs = new Dictionary<string, byte[]>();
			foreach (var eku in m_Policy.EKUs)
            {
				if (eku.Value.Length > 0xff) throw new InvalidDataException(string.Format("EKU {0} ({1}) is too long, length {2} over 255", eku.FriendlyName, eku.ID, eku.Value.Length));
				EKUs.Add(eku.ID, eku.Value);
            }
			// parse scenarios into a dict
			var Scenarios = new Dictionary<string, SigningScenario>(m_Policy.SigningScenarios.Length);
			foreach (var scenario in m_Policy.SigningScenarios)
				Scenarios.Add(scenario.ID, scenario);
			// parse the signers.
			var EmittedSigners = new Dictionary<string, uint>();
			uint numSigners = 0;
			foreach (var signer in m_Policy.Signers)
            {
				// get the root certificate;
				// either an ID of a root certificate known to mincrypt (hardcoded roots, or unknown, or self-signed)
				// or a SHA256 hash of the data from this certificate that would be used if it were "to be signed".

				EmittedSigners.Add(signer.ID, numSigners);
				var regKey = string.Format(Constants.KEY_CI_SIGNER_FORMAT, numSigners);
				switch (signer.CertRoot.Type)
                {
					case CertEnumType.Wellknown:
						ret.Add(NewRegistryEntry(regKey, Constants.VALUE_CI_SIGNER_KNOWNROOT, signer.CertRoot.Value[0]));
						break;
					case CertEnumType.TBS:
						ret.Add(NewRegistryEntry(regKey, Constants.VALUE_CI_SIGNER_TBSHASH, signer.CertRoot.Value));
						if (signer.CertRoot.TbsHashAlgorithmSpecified)
							ret.Add(NewRegistryEntry(regKey, Constants.VALUE_CI_HASH_ALGORITHM, signer.CertRoot.TbsHashAlgorithm));
						break;
                }

				// Serialise the EKUs.
				// byte numEkus; followed by single-byte length prefixed EKUs.
				if (signer.CertEKU?.Length > 0)
				{
					var ekuBytes = new List<byte>();
					var numEkus = signer.CertEKU.Length;
					byte lengthByte = (byte)numEkus;
					if (numEkus > 0xff) lengthByte = 0xff;
					ekuBytes.Add(lengthByte);
					foreach (var eku in signer.CertEKU)
                    {
						var bytes = EKUs[eku.ID];
						ekuBytes.Add((byte)bytes.Length);
						ekuBytes.AddRange(EKUs[eku.ID]);
                    }
					ret.Add(NewRegistryEntry(regKey, Constants.VALUE_CI_SIGNER_EKUS, ekuBytes.ToArray()));
				}

				numSigners++;
            }
			// add the signer count
			if (numSigners != 0)
			{
				ret.Add(NewRegistryEntry(Constants.KEY_CI_SIGNERS, Constants.VALUE_CI_SIGNERS_COUNT, numSigners));
			}
			foreach (var ci in m_Policy.SigningScenarios)
			{
				if (!s_ValidScenarios.Contains(ci.Value)) throw new InvalidDataException(string.Format("Invalid signing scenario value {0}.", ci.ID));

				// Get every valid scenario ID inherited by this one.
				HashSet<string> InheritedIDs;
				if (ci.InheritedScenarios == null) InheritedIDs = new HashSet<string>();
				else InheritedIDs = new HashSet<string>(ci.InheritedScenarios.Split(',').Where((x) => Scenarios.ContainsKey(x)).Distinct());
				// Keep merging down, inherited scenarios could inherit more.
				{
					IEnumerable<string> NextSet = InheritedIDs;

					bool lastOne = false;
					do
					{
						NextSet = NextSet.SelectMany((next) =>
						{
							var self = Scenarios[next];
							if (self.InheritedScenarios == null) return Enumerable.Empty<string>();
							return self.InheritedScenarios.Split(',').Where((x) => Scenarios.ContainsKey(x) && !InheritedIDs.Contains(x));
						}).Where((x) => x != null).Distinct();
						lastOne = !NextSet.Any();
						InheritedIDs.UnionWith(NextSet);
					} while (!lastOne);
				}

				// Get inherited signing scenario followed by this one.
				var WithInherited = InheritedIDs.Select((x) => Scenarios[x]).Append(ci).Where((x) => x != null);

				var scenarioKey = string.Format(Constants.KEY_CI_SCENARIO_FORMAT, ci.Value);

				// For each signing scenario, provide a u32 array of signer indices.
				var AllProductionSigners = WithInherited.Select((x) => x.ProductSigners).Where((x) => x != null).SelectMany((x) => x);
				var AllTestSigners = WithInherited.Select((x) => x.TestSigners).Where((x) => x != null).SelectMany((x) => x);
				var AllTestSigningSigners = WithInherited.Select((x) => x.TestSigningSigners).Where((x) => x != null).SelectMany((x) => x);
				AddSigningScenarioToRegistry(scenarioKey, AllProductionSigners, Constants.VALUE_CI_SCENARIO_SIGNERS_PRODUCTION, EmittedSigners, ret);
				AddSigningScenarioToRegistry(scenarioKey, AllTestSigners, Constants.VALUE_CI_SCENARIO_SIGNERS_TEST, EmittedSigners, ret);
				AddSigningScenarioToRegistry(scenarioKey, AllTestSigningSigners, Constants.VALUE_CI_SCENARIO_SIGNERS_TESTSIGNING, EmittedSigners, ret);

				// Provide the minimum hash algorithm used for this scenario.
				HashAlgorithmType? minimumHash = WithInherited.Where((x) => x.MinimumHashAlgorithmSpecified)
					.Select((x) => new HashAlgorithmType?(x.MinimumHashAlgorithm)).OrderByDescending((x) => x.Value).FirstOrDefault();
				if (minimumHash.HasValue)
					ret.Add(NewRegistryEntry(scenarioKey, Constants.VALUE_CI_HASH_ALGORITHM, s_HashAlgorithmToCalg[minimumHash.Value]));
			}

			return ret;
		}

		private static void AddSigningScenarioToRegistry(string scenarioKey, IEnumerable<CiSigner> signers, string name, Dictionary<string, uint> knownSigners, List<Setting> registry)
        {
			var arr = new List<uint>();
			foreach (var signer in signers)
            {
				arr.Add(knownSigners[signer.SignerId]);
            }
			if (arr.Count == 0) return;
			registry.Add(NewRegistryEntry(scenarioKey, name, arr.OrderBy((x) => x).ToArray()));
        }

		private static void WriteRawString(BinaryWriter writer, string value)
        {
			var strBytes = Encoding.Unicode.GetBytes(value);
			if (strBytes.Length > ushort.MaxValue) throw new ArgumentOutOfRangeException("Strings have a maximum length of 32767 characters");
			writer.Write((ushort)strBytes.Length);
			writer.Write(strBytes);
			writer.Flush();
		}

		private static void WriteValue(BinaryWriter writer, SettingValueType value, bool ifFveWithTpm = false, bool ifVbs = false)
        {
			ushort flags = 0;
			if (ifFveWithTpm) flags |= 0x20;
			if (ifVbs) flags |= 0x40;
			switch (value.Item)
            {
				case string str:
					//flags |= 0;
					writer.Write(flags);
					WriteRawString(writer, str);
					break;
				case bool boolean:
					{
						flags |= 1;
						writer.Write(flags);
						ushort serialised = 0;
						if (boolean) serialised = 1;
						writer.Write(serialised);
					}
					break;
				case uint dword:
					flags |= 2;
					writer.Write(flags);
					writer.Write(dword);
					break;
				case DWordRangeType range32:
					flags |= 3;
					writer.Write(flags);
					writer.Write(range32.Default);
					writer.Write(range32.LowerBound);
					writer.Write(range32.UpperBound);
					break;
				case DWordArrayType choice32:
					flags |= 4;
					writer.Write(flags);
					writer.Write(choice32.Default);
					if (choice32.Values.Length > ushort.MaxValue) throw new ArgumentOutOfRangeException("Arrays have a maximum length of 65535 elements");
					writer.Write((ushort)choice32.Values.Length);
					foreach (var val in choice32.Values) writer.Write(val);
					break;
				case ulong qword:
					flags |= 5;
					writer.Write(flags);
					writer.Write(qword);
					break;
				case QWordRangeType range64:
					flags |= 6;
					writer.Write(flags);
					writer.Write(range64.Default);
					writer.Write(range64.LowerBound);
					writer.Write(range64.UpperBound);
					break;
				case QWordArrayType choice64:
					flags |= 7;
					writer.Write(flags);
					writer.Write(choice64.Default);
					if (choice64.Values.Length > ushort.MaxValue) throw new ArgumentOutOfRangeException("Arrays have a maximum length of 65535 elements");
					writer.Write((ushort)choice64.Values.Length);
					foreach (var val in choice64.Values) writer.Write(val);
					break;
				case BcdRuleOptionType option:
					{
						flags |= 8;
						writer.Write(flags);
						ushort serialised = 0;
						if (option == BcdRuleOptionType.Enforced) serialised = 1;
						writer.Write(serialised);
					}
					break;
				case byte[] bytes:
					flags |= 10;
					writer.Write(flags);
					if (bytes.Length > ushort.MaxValue) throw new ArgumentOutOfRangeException("Byte arrays have a maximum length of 65535 bytes");
					writer.Write((ushort) bytes.Length);
					writer.Write(bytes);
					break;
				default:
					throw new ArgumentOutOfRangeException("Unsupported setting value");
			}
			writer.Flush();
        }
	}
}
