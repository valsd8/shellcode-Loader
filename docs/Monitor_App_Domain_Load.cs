using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Clr;
using Microsoft.Diagnostics.Tracing.Session;
using System;

namespace MonitorEtw
{
    internal class Program
    {
        static void Main(string[] args)
        {
            using (var session = new TraceEventSession("MyDotNetMonitor"))
            {
                // 1. Enable CLR provider
                session.EnableProvider(
                    ClrTraceEventParser.ProviderGuid,
                    TraceEventLevel.Informational,
                    (ulong)ClrTraceEventParser.Keywords.Loader);

                // 2. Event handlers
                session.Source.Clr.LoaderAppDomainLoad += data =>
                {
                    Console.WriteLine($"AppDomain: {data.AppDomainName}");
                };

                session.Source.Clr.LoaderModuleLoad += data =>
                {
                    var path = data.ModuleILPath?.ToLowerInvariant();

                    if (path == null) return;

                    if (path.Contains("microsoft") ||
                        path.Contains("visual studio") ||
                        path.Contains("gac") ||
                        path.Contains("system.runtime"))
                        return;

                    Console.WriteLine($"Module: {data.ModuleILPath}");
                };

                // 3. Run
                Console.WriteLine("Listening for events... Press Ctrl+C to stop.");
                session.Source.Process();
            }
        }
    }
}