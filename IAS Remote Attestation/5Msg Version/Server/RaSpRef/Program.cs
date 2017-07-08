//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

using Microsoft.Owin.Hosting;
using System;
using System.Collections.Generic;
using System.Net.Http;
using log4net;
using log4net.Config;
using System.Reflection;
using SgxOptions;



namespace RaSpRef
{
    class Program
    {
        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);


        static void Main(string[] args)
        {
           var options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log, args);

           try
            {
                options.ParseOptions();
                options.PrintBanner();
                log.Debug("application starting");

                // Check if an error occurred while parsing command line options and only
                // run the server if we didn't have any.
                if (!options.invalidOption)
                {
                    string urlString = Properties.Settings.Default.SPUri;

                    // Using the route map defined with the OWIN interface via: 
                    // Configuration(IAppBuilder ?AppBuilder) in the startup file, 
                    // start the server with defalut settings for now.
                    using (WebApp.Start<SpStartup>(url: urlString))
                    {
                        Console.WriteLine("Server Started for: {0}", urlString);
                        Console.WriteLine();
                        Console.ReadLine();
                    }
                }
            }
            catch (System.Reflection.TargetInvocationException e)
            {
                Exception ie;
                options.LogCaughtErrorException(e);
                Console.WriteLine("RA Server failed to establish connection.");
                Console.WriteLine("Is there an instance of this server already running?");
                Console.WriteLine("Exception Details:");
                for (ie = e; ie != null; ie = ie.InnerException)
                {
                    Console.WriteLine("  {0}", ie.Message);
                }
            }
            finally
            {
                log.Info("application ending");
            }
        }


    }
}
