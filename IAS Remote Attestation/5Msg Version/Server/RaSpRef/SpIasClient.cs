//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using log4net;
using System.Reflection;
using SgxOptions;

namespace RaSpRef
{
    public class IasProxy
    {
        // If the connection to the IAS server will be made via HTTP Proxy tunneling from inside a firewall, let the WebRequestHandler instance know about that.
        public static WebRequestHandler iasHandlerWithProxy = new WebRequestHandler
        {
            UseProxy = true,
            Proxy = new WebProxy(Properties.Settings.Default.IASProxyUri),
            ClientCertificateOptions = ClientCertificateOption.Manual
        };
    }

    public sealed class SpIasConnectionManager
    {
        private BuildMessage bMessage = new BuildMessage();
        public WebRequestHandler iasHandler;

        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);

        // The HttpClient is publicly accessable, but the singleton wrapper allows only one instance to exist.
        // Excetution order creates the client property after the handler has been initialized.
        public HttpClient iasClient;

        public byte[] SPID = null;
        public bool LinkableQuotes = false;
        public bool UseIAS = false;
        public Uri iasUri = null;

        //Create a new instance of RSACryptoServiceProvider.
        public RSACryptoServiceProvider RSA = null;

        // Setup the client handler for HTTP proxy tunneling if needed
        private static void InitWrHandler(WebRequestHandler wrhandler)
        {
            if (wrhandler == null)
            {
                Exception e = new System.ArgumentNullException("wrhandler");
                options.LogThrownException(e);
                throw e;
            }

            // NOTE: System Store "MY" corresponds to the current user's certificate store.
            // This code assumes that the IAS server's certificate and key (in PFX form) have been installed in the current user's certificate store.
            X509Store localHostCertStore = new X509Store(Constants.CurrentUserCertStore, StoreLocation.CurrentUser);
            
            localHostCertStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection usersFullCollection = (X509Certificate2Collection)localHostCertStore.Certificates;                

            string subjectName = Properties.Settings.Default.IASCertSubject;

            X509Certificate2Collection iasCollection = (X509Certificate2Collection)usersFullCollection.Find(X509FindType.FindBySubjectName, subjectName, false);
            X509Certificate2 iasCert = iasCollection.Find(X509FindType.FindBySubjectName, subjectName, false)[0];
            wrhandler.ClientCertificates.Add(iasCert);
        }

        private WebRequestHandler iasHandlerWithoutProxy = new WebRequestHandler
        {
            UseProxy = false,
            ClientCertificateOptions = ClientCertificateOption.Manual
        };

        public SpIasConnectionManager()  
        {
            try
            {
                if (Properties.Settings.Default.UseIAS)
                {
                    log.Debug("UseIAS = true");
                    UseIAS = true;

                    // Check for valid IAS uri
                    iasUri = new Uri(Properties.Settings.Default.IASUri);
                    log.DebugFormat("IASUri {0} passes Uri test", iasUri);

                    // Check for valid proxy
                    if (String.IsNullOrWhiteSpace(Properties.Settings.Default.IASProxyUri))
                    {
                        log.Debug("IASProxyUri is empty -- no proxy will be used");
                        iasHandler = iasHandlerWithoutProxy;
                    }
                    else
                    {
                        Uri proxyUri = new Uri(Properties.Settings.Default.IASProxyUri);
                        log.DebugFormat("IASProxyUri {0} passes Uri test", proxyUri);
                        iasHandler = IasProxy.iasHandlerWithProxy;
                    }

                    InitWrHandler(iasHandler);
                    log.Debug("IAS certificate is installed on RA Server");

                    // Set up Report Key
                    // Create a new instance of RSAParameters.
                    RSAParameters RSAKeyInfo = new RSAParameters();
                    if (String.IsNullOrWhiteSpace(Properties.Settings.Default.RKMod) || 
                        String.IsNullOrWhiteSpace(Properties.Settings.Default.RKExp))
                        throw new Exception("Invalid Report Key parameter(s)");
                    RSAKeyInfo.Modulus = bMessage.BlobStrToBa(Properties.Settings.Default.RKMod);
                    RSAKeyInfo.Exponent = bMessage.BlobStrToBa(Properties.Settings.Default.RKExp);
                    //Import key parameters into RSA.
                    RSA = new RSACryptoServiceProvider();
                    RSA.ImportParameters(RSAKeyInfo);
            
                    // Set up SPID -- require real value to be used
                    if (String.IsNullOrWhiteSpace(Properties.Settings.Default.SPID))
                        throw new Exception();
                    else                       
                        SPID = bMessage.BlobStrToBa(Properties.Settings.Default.SPID);
                }
                else
                {
                    log.Debug("UseIAS = false");
                    UseIAS = false;

                    // Set up SPID for UseIAS=False
                    if (String.IsNullOrWhiteSpace(Properties.Settings.Default.SPID))
                        SPID = Constants.spIdba;
                    else
                        SPID = bMessage.BlobStrToBa(Properties.Settings.Default.SPID);
                }
                log.DebugFormat("SPID = {0}", bMessage.BaToBlobStr(SPID));

                // Set up LinkableQuotes
                if (Properties.Settings.Default.LinkableQuotes)
                {
                    LinkableQuotes = true;
                    log.Debug("Linkable Quotes = true");
                }
                else
                {
                    LinkableQuotes = false;
                    log.Debug("Linkable Quotes = false");
                }
                return;

            }
            catch (Exception e)
            {
                throw new Exception("Failed to initialize SpIasConnectionManager." + e.Message);
            }

        }

    } // End SpIasConnectionManager definition
}
