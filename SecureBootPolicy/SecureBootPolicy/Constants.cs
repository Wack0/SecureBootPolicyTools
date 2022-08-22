using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureBootPolicy
{
    internal static class Constants
    {

        internal const byte ID_SIGNINGSCENARIO_ENTERPRISE = 2; // used by ci.dll only
        internal const byte ID_SIGNINGSCENARIO_CUSTOM1 = 3; // used by ci.dll only
        internal const byte ID_SIGNINGSCENARIO_AUTHENTICODE = 4; // used by ci.dll only
        internal const byte ID_SIGNINGSCENARIO_CUSTOM2 = 5; // used by ci.dll only
        internal const byte ID_SIGNINGSCENARIO_STORE = 6; // used by ci.dll only
        internal const byte ID_SIGNINGSCENARIO_ANTIMALWARE = 7; // used by ci.dll only
        internal const byte ID_SIGNINGSCENARIO_MICROSOFT = 8; // used by ci.dll only
        internal const byte ID_SIGNINGSCENARIO_CUSTOM4 = 9; // used by ci.dll only ; "custom3" is now antimalware
        internal const byte ID_SIGNINGSCENARIO_CUSTOM5 = 10; // used by ci.dll only
        internal const byte ID_SIGNINGSCENARIO_DYNAMIC_CODEGEN = 11; // used by ci.dll only
        internal const byte ID_SIGNINGSCENARIO_WINDOWS = 12; // used by boot applications and ci.dll
        internal const byte ID_SIGNINGSCENARIO_CUSTOM7 = 13; // used by ci.dll only
        internal const byte ID_SIGNINGSCENARIO_WINDOWS_TCB = 14; // used by ci.dll only
        internal const byte ID_SIGNINGSCENARIO_CUSTOM6 = 15; // used by ci.dll only
        internal const byte ID_SIGNINGSCENARIO_BOOT_APPS = 128;
        internal const byte ID_SIGNINGSCENARIO_HAL_EXTENSIONS = 129;
        internal const byte ID_SIGNINGSCENARIO_ELAM_DRIVERS = 130;
        internal const byte ID_SIGNINGSCENARIO_DRIVERS = 131;
        internal const byte ID_SIGNINGSCENARIO_BOOT_REVOCATION_LIST = 132;
        internal const byte ID_SIGNINGSCENARIO_FIRMWARE_UPDATE = 134;
        internal const byte ID_SIGNINGSCENARIO_DRM = 135; // used by ci.dll only
        internal const byte ID_SIGNINGSCENARIO_CORE_EXTENSIONS = 136;
        internal const byte ID_SIGNINGSCENARIO_PLATFORM_MANIFEST_REQUIRED = 137;
        internal const byte ID_SIGNINGSCENARIO_RUNTIME_REVOCATION_LIST = 133; // used by boot applications and ci.dll
        internal const byte ID_SIGNINGSCENARIO_PLATFORM_MANIFEST = 138;
        internal const byte ID_SIGNINGSCENARIO_FLASHING = 139;

        internal const string KEY_CI_SIGNERS = "CI\\Signers";
        internal const string VALUE_CI_SIGNERS_COUNT = "Count";

        internal const string KEY_CI_SIGNER_FORMAT = "CI\\Signers\\{0}";
        internal const string VALUE_CI_SIGNER_KNOWNROOT = "KnownRoot";
        internal const string VALUE_CI_SIGNER_TBSHASH = "TBS";
        internal const string VALUE_CI_SIGNER_EKUS = "EKUs";

        internal const string KEY_CI_SCENARIO_FORMAT = "CI\\Scenarios\\{0}";
        internal const string VALUE_CI_SCENARIO_SIGNERS_PRODUCTION = "ProductionSigners";
        internal const string VALUE_CI_SCENARIO_SIGNERS_TEST = "TestSigners";
        internal const string VALUE_CI_SCENARIO_SIGNERS_TESTSIGNING = "TestsigningSigners";

        internal const string VALUE_CI_HASH_ALGORITHM = "Hash";

        internal const string KEY_DEVICEID = "Debug";
        internal const string VALUE_DEVICEID = "DeviceID";

        internal const uint HKEY_SECUREBOOT_POLICIES_ROOT = 0x81000000;
    }
}
