//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Results;
using System.Net.Http;
using System.Net.Http.Headers;
using log4net;
using System.Reflection;
using SgxOptions;
using Newtonsoft.Json;

namespace RaSpRef
{
    class Msg0
    {
        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);

        /// <summary>
        /// Process Message 0
        /// </summary>
        /// <param name="Request">Client Provisioning request</param>
        /// <param name="sigmaSequenceCheck">Service Provider Sequence (State) Check</param>
        /// <returns>Message 0 response</returns>
        public M0ResponseMessage ProcessMessage0(HttpRequestMessage Request, SpSequenceCheck sigmaSequenceCheck)
        {
            log.Debug("ProcessMessage0(.) started.");

            if (Request == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.BadRequest);
                options.LogThrownException(e);
                throw e;
            }

            if (sigmaSequenceCheck == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // Check and parse Message 0
            M0RequestMessage m0Received = VerifyMessage0IsValid(Request, sigmaSequenceCheck);
            if (m0Received == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            M0ResponseMessage msg0Response = new M0ResponseMessage();
            msg0Response.respHeader.sessionNonce = m0Received.reqHeader.nonce;

            // Successful process of Message 0
            log.Debug("ProcessMessage0(.) returning.");
            return msg0Response;
        }

        /// <summary>
        /// Verify that Message 0 is valid
        /// </summary>
        /// <param name="Request">Client Message 0 Response</param>
        /// <param name="sigmaSequenceCheck">Service Provider Sequence (State) Check</param>
        /// <returns>Parsed and validated Message 0</returns>
        private M0RequestMessage VerifyMessage0IsValid(HttpRequestMessage request, SpSequenceCheck sigmaSequenceCheck)
        {
            log.Debug("VerifyMessage0IsValid(.) started.");

            if (request == null || sigmaSequenceCheck == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // Update Client state
            if (!sigmaSequenceCheck.UpdateState(Constants.SequenceState.Msg0))
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.PreconditionFailed);
                options.LogThrownException(e);
                throw e;
            }

            // Check m0 and if valid, process
            var result = request.Content.ReadAsStringAsync();
            string jsonMsg0Request = result.Result;

            M0RequestMessage m0Received = new M0RequestMessage();
            try
            {
                m0Received = JsonConvert.DeserializeObject<M0RequestMessage>(jsonMsg0Request);
            }
            catch (Exception msg0reqError)
            {
                options.LogCaughtErrorException(msg0reqError);
                log.DebugFormat("******* Message 0 JSON Content Error: {0}", msg0reqError);
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            string m0ReceivedString = m0Received.GetMsgString();
            log.Info("******* Received M0 Request");
            log.DebugFormat("{0}{1}", request.Headers, jsonMsg0Request);
            log.DebugFormat("M0 Base 16 Encoded String: {0}", m0ReceivedString);

            // Check the nonce and the base16 encoded length of the inbound request
            bool nonceCheckSuccess = false;
            try
            {
                log.Debug("Checking nonce");
                nonceCheckSuccess = sigmaSequenceCheck.currentNonce.SequenceEqual(m0Received.reqHeader.nonce);
            }
            catch (Exception e)
            {
                options.LogCaughtErrorException(e);
                log.DebugFormat("****Message 0 Nonce Error: {0}", e);
                HttpResponseException newException = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(newException);
                throw newException;
            }

            if (!nonceCheckSuccess)
            {
                log.Debug("Msg0 Nonce check failed");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            // Compare the reported length against the actual length (base16 string length/2)
            // Could BigEndian a replay attempt if the nonce field does not match. 
            // Could also be other tampering if other fields do not pass checks.
            // Restart the session, and reject the request.
            if (!(BitConverter.ToUInt32(m0Received.reqHeader.msgLength, 0) == (m0ReceivedString.Length / 2)))
            {
                log.Debug("Msg0 Message length check failed");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            if (m0Received.reqM0Body.ExtGID.SequenceEqual(MsgInitValues.DS_EMPTY_BA4))
            {
                log.Debug("Msg0: Extended GID wasn't sent");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            // NOTE: Extended GID = 0 indicates that IAS is selected for enclave verification.
            // This Service Provider only supports IAS for enclave verification at this time.
            // Note to ISV: if non-Intel Attestation Service (i.e. Extended GID != 0) is being used, replace this logic
            //      to point to your service.
            if (!m0Received.reqM0Body.ExtGID.SequenceEqual(MsgInitValues.DS_ZERO_BA4))
            {
                log.Debug("Msg0: Invalid Extended GID. This server only processes Extended GID = 0");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Unauthorized);
                options.LogThrownException(e);
                throw e;
            }

            log.Debug("VerifyMessage0IsValid(.) returning.");
            return m0Received;
        }

    }
}
