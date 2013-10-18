using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Hosting;

namespace WebApiBook.Security.ResourceServer1
{
    class Program
    {
        static void Main(string[] args)
        {
            const string baseUri = "http://resourceserver.example:8000";
            Trace.Listeners.Add(new ConsoleTraceListener());
            using (WebApp.Start<Startup>(new StartOptions(baseUri)))
            {
                Console.WriteLine("Application is started...");
                Client.Run().Wait();
                Console.ReadKey();
            }
        }
    }
}
