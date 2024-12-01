﻿using River;
using River.Internal;
using River.ShadowSocks;
using River.Socks;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace RiverApp
{
    class Program
    {
        static Trace Trace = River.Trace.Default;

        static void Main(string[] args)
        {
            if (MainHandler(args))
            {
                Console.WriteLine("Press any key to stop . . .");
                Console.ReadLine();
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        static bool MainHandler(string[] args)
        {
            Trace.WriteLine(TraceCategory.Misc, "Logger started...");
            RiverInit.RegAll();

            var servers = new List<(RiverServer server, Uri uri)>();
            var forwarders = new List<string>();

            for (var i = 0; i < args.Length; i++)
            {
                //去除换行符
                args[i]= args[i].Replace("\r", "").Replace("\n", "");
                switch (args[i].ToUpperInvariant())
                {
                    case "-NAME":
                        {
                            ShutdownRequestTracker.Instance.AddTracker(args[++i]);
                            break;
                        }
                    case "STOP":
                        {
                            ShutdownRequestTracker.Instance.RequestStop(args[++i]);
                            return false;
                        }
                    case "-L":
                        {
                            // Listen
                            var listener = args[++i];
                            var uri = new Uri(listener);
                            var serverType = Resolver.GetServerType(uri);
                            if (serverType == null)
                            {
                                throw new Exception($"Server type {uri.Scheme} is unknown");
                            }
                            var server = (RiverServer)Activator.CreateInstance(serverType);
                            servers.Add((server, uri));
                            break;
                        }
                    case "-F":
                        {
                            // Forward
                            var proxy = args[++i];
                            forwarders.Add(proxy);
                            break;
                        }
                    case "-VERSION":
                        {
                            Console.WriteLine("Version 0.8.9");
                            break;
                        }
                    case "-EVENTLOG":
                        {
                            Console.WriteLine("Generting event log...");
                            if (int.TryParse(args[++i], out var eventId))
                            {
                                using (var eventLog = new System.Diagnostics.EventLog("Application"))
                                {
                                    eventLog.Source = "Application";
                                    eventLog.WriteEntry("EventLogTriggeer", System.Diagnostics.EventLogEntryType.Information, eventId);
                                }
                            }
                            break;
                        }

                    default:
                        break;
                }
            }

            for (var index = 0; index < servers.Count; index++)
            {
                var (server, uri) = servers[index];
                // for (var i = 0; i < forwarders.Count; i++)
                for (var i = 0; i <= index; i++)
                {
                    var fwd = forwarders[i];
                    // var fwd = forwarders[index];
                    server.Chain.Add(fwd);
                }

                server.Run(uri);
            }

            return servers.Any();
        }
    }
}
