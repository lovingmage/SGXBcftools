//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using log4net;
using System.Reflection;
using SgxOptions;
using System.IO;
using Newtonsoft.Json;
using System.Web.Http;
using System.Net.Http;
using System.Net.Http.Headers;


namespace RaSpRef
{
    class SpSequenceCheck
    {
        private readonly object mLock = new Object();

        // Create Session Nonce
        private RNGCryptoServiceProvider nonceGen = new RNGCryptoServiceProvider();
        
        public EnclaveType enclaveType = new EnclaveType();
        public HttpClient iasClient = null;

        public byte[] currentGa { get; set; }
        public byte[] currentGb { get; set; }
        public byte[] currentKDK { get; set; }
        public byte[] currentSmk { get; set; }
        public byte[] currentNonce { get; set; }
        public bool provisioningInProgress { get; set; }
        public bool m0Received { get; set; }
        public bool m1Received { get; set; }
        public bool m3Received { get; set; }
       
        // To manage state for provisioning request sequence
        private Constants.SequenceState currentState = Constants.SequenceState.None;

        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);

        public SpSequenceCheck()
        {
            log.Debug("SpSequenceCheck(.) started.");
            SequenceStateInit();
            log.Debug("SpSequenceCheck(.) returning.");
        }

        public void SequenceStateInit()
        {
            log.Debug("SequenceStateInit(.) started.");

            currentGa = null;
            currentGb = null;
            currentKDK = null;
            currentSmk = null;

            lock (mLock)
            {
                // Create Nonce/ID for the transaction
                currentNonce = Constants.sn1;
                for (int i = 0; i < 5; i++)
                {
                    nonceGen.GetBytes(currentNonce);
                }

            }

            provisioningInProgress = false;
            m0Received = false;
            m1Received = false;
            m3Received = false;
            if (SpStartup.iasConnectionMgr.UseIAS)
            {
                iasClient = new HttpClient(SpStartup.iasConnectionMgr.iasHandler);

                // Negotiate acceptance of JSON from IAS          
                iasClient.DefaultRequestHeaders.Accept.Clear();
                iasClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            }
            log.Debug("SequenceStateInit(.) returning.");
        }

        /// <summary>
        /// Updates the state to the provided state, if valid
        /// </summary>
        /// <param name="newState"></param>
        /// <returns>Boolean of whether the state was updated or not</returns>
        public bool UpdateState(Constants.SequenceState newState)
        {
            log.Debug("UpdateState(.) started.");

            // Check that the new state is directly after the last state (sequential change)
            int state = ((int)newState - (int)currentState);
            if (state == 1)
            {
                currentState = newState;
                log.Debug("UpdateState(.) returning true.");
                return true;
            }

            log.Debug("Invalid state change from " + currentState.ToString() + " to " + newState.ToString());

            log.Debug("UpdateState(.) returning false.");
            return false;
        }

        public void SetEnclaveType(String MRSIGNERString, ushort ISVPRODID)
        {
            log.Debug("SetEnclaveType(.) started.");

            enclaveType = SpStartup.enclaveTypeList.EnclaveType.Find(x => (x.MRSIGNER == MRSIGNERString && x.ISVPRODID == ISVPRODID));

            if (enclaveType == null)
            {
                log.Debug("No valid enclave type (defined by MRSIGNER and ISVPRODID) found for the received message.");
                Exception e = new HttpResponseException(System.Net.HttpStatusCode.PreconditionFailed);
                options.LogThrownException(e);
                throw e;

            }

            log.Debug("Enclave type settings for this session:");
            log.DebugFormat("Name = {0}", enclaveType.Name);
            log.DebugFormat("MRSIGNER = {0}", enclaveType.MRSIGNER);
            log.DebugFormat("ISVPRODID = {0}", enclaveType.ISVPRODID);
            log.DebugFormat("ISVSVNMinLevel = {0}", enclaveType.ISVSVNMinLevel);
            log.DebugFormat("MRENCLAVE = {0}", enclaveType.MRENCLAVE);
            log.DebugFormat("LeaseDuration = {0}", enclaveType.LeaseDuration);
            log.DebugFormat("LeaseDurationTimeUnit = {0}", enclaveType.LeaseDurationTimeUnit);
            log.DebugFormat("TrustEnclaveGroupOutOfDate = {0}", enclaveType.TrustEnclaveGroupOutOfDate);
            log.DebugFormat("TrustPSEOutOfDate = {0}", enclaveType.TrustPSEOutOfDate);
            log.DebugFormat("IsProductionEnclave = {0}", enclaveType.IsProductionEnclave);

            log.Debug("SetEnclaveType(.) returning.");
            return;

        }


    }
}
