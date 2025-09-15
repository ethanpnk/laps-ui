using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Management.Automation;

namespace LapsUiHost;

class Program
{
    static void Main(string[] args)
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var ps = PowerShell.Create();

        RunScript(ps, assembly, "LAPS-UI.ps1");
        RunScript(ps, assembly, "Updater.ps1");
    }

    static void RunScript(PowerShell ps, Assembly assembly, string name)
    {
        var resourceName = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith(name, StringComparison.OrdinalIgnoreCase));
        if (resourceName == null)
        {
            Console.Error.WriteLine($"Resource '{name}' not found.");
            return;
        }

        using var stream = assembly.GetManifestResourceStream(resourceName);
        using var reader = new StreamReader(stream!);
        var script = reader.ReadToEnd();

        ps.Commands.Clear();
        ps.AddScript(script);
        ps.Invoke();

        if (ps.HadErrors)
        {
            foreach (var error in ps.Streams.Error)
            {
                Console.Error.WriteLine(error);
            }
        }
    }
}
