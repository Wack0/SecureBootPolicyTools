using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecureBootPolicy;
using System.Reflection;
using System.IO;

namespace SecureBootPolicyCompiler
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: {0} inputPolicy.xml outputPolicy.bin", Path.GetFileName(Assembly.GetExecutingAssembly().Location));
                return;
            }

            var input = args[0];
            var output = args[1];

            var inPolicy = new XmlPolicy(input);
            inPolicy.ConvertToBinaryFile(output);
        }
    }
}
