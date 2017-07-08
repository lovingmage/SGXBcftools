//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

using Owin;
using System.Web.Http;
using log4net;
using System.Reflection;
using SgxOptions;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using Newtonsoft.Json;


namespace RaSpRef
{
    class SpStartup
    {
        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        public static EnclaveTypeList enclaveTypeList = null;
        public static SpIasConnectionManager iasConnectionMgr = null;
        private static SgxOptions.SgxOptions options = null;

        /// <summary>
        /// Checks that all settings in the config file exist
        /// </summary>
        private void LoadEnclaveSettings()
        {
            log.Debug("LoadEnclaveSettings(.) started.");

            // Verify that all enclave settings are valid
            try
            {
                // Load enclave types
                if (!File.Exists(@".\EnclaveTypeList.json"))
                {
                    log.Debug("Unable to find EnclaveTypeList.json");
                    throw new FileNotFoundException();
                }
                enclaveTypeList = JsonConvert.DeserializeObject<EnclaveTypeList>(File.ReadAllText(@".\EnclaveTypeList.json"));
                if (enclaveTypeList == null)
                {
                    log.Debug("Unable to read EnclaveTypeList.json");
                    throw new FileLoadException();
                }

            }
            catch (Exception e)
            {
                options.LogCaughtErrorException(e);
                log.Debug("Failed to load enclave type settings. " + e.Message);
                Exception eNew = new Exception("Failed to verify all enclave type settings");
                options.LogThrownException(eNew);
                throw eNew;
            }
        }

        public void Configuration(IAppBuilder spAppBuilder)
        {
           if (options == null)
           {
              options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);
           }

           log.Debug("Configuration(.) started.");

           try
           {
              HttpConfiguration spconfig = new HttpConfiguration();
              spconfig.Routes.MapHttpRoute(
                 name: Constants.DefaultApi,
                 routeTemplate: Constants.RouteTemplate,
                 defaults: new { id = RouteParameter.Optional });
              spAppBuilder.UseWebApi(spconfig);

              LoadEnclaveSettings();

              iasConnectionMgr = new SpIasConnectionManager();
           }
           catch (Exception e)
            {
                options.LogThrownException(e);
                log.Debug("Failed to set up HTTP, proxy, or IAS connection - check settings");
                throw e;
            }

           finally
           {
              log.Debug("Configuration(.) returning.");
           }
        }       
    }
}
