//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

using System;
using System.Linq;
using System.Collections.Generic;
using System.Web.Http;
using System.Web.Http.Results;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using System.Text;
using IppDotNetWrapper;
using System.Threading;
using System.Threading.Tasks;
using log4net;
using System.Reflection;
using SgxOptions;

namespace RaSpRef
{
    class ProvisionRequest
    {
        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);

        private BuildMessage bMessage = new BuildMessage();

        public ChallengeResponse ProcessProvisionRequest(HttpRequestMessage Request, ClientTransaction client)
        {
            if (Request == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // Update client state
            if (client == null || !client.sigmaSequenceCheck.UpdateState(Constants.SequenceState.Provision))
                throw new HttpResponseException(System.Net.HttpStatusCode.PreconditionFailed);

            // For a non-local server scenario, a timing 
            // method that dumps the pseudo session and reinitializes the 
            // sigmaSequenceCheck object after some time has elapsed should be implemented.
            // Look at the incoming request content and verify the request.
            var result = Request.Content.ReadAsStringAsync();
            string jsonProvRequest = result.Result;
            
            ProvisionRequestMessage provReqRecieved = new ProvisionRequestMessage();
            try
            {
                provReqRecieved = JsonConvert.DeserializeObject<ProvisionRequestMessage>(jsonProvRequest);
            }
            catch (Exception provReqError)
            {
                log.DebugFormat("******* Provisioning Request JSON Content Error: {0}", provReqError);
                throw new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
            }

            string recievedPstring = provReqRecieved.GetMsgString();

            log.DebugFormat("Received Provisioning Request: {0}{1}", Request.Headers, jsonProvRequest);
            log.DebugFormat("Prov Base16 Encoded String: {0}", recievedPstring);
            
            // Validate the recieved provisioning request
            // If the server received a valid request, create the response.
            // Since the provisioning request is fixed and known in advance, 
            // build a reference base16 representation and compare
            // with a similar base16 representation of the recieved message.
            ProvisionRequestMessage referenceP = new ProvisionRequestMessage();
            string refPstring = null;
            bMessage.buildProvisioningRequest(out referenceP, out refPstring);

            // Compare base16 encoded message strings and if equal, start 
            // the sequence by returning a challenge response.
            // Since this was a valid provisioning request, create the challenge response.
            ChallengeResponse challengeResponseMessage = new RaSpRef.ChallengeResponse();

            // Build a populated challenge response object
            bMessage.buildChallengeResponse(out challengeResponseMessage);
            challengeResponseMessage.respHeader.sessionNonce = client.sigmaSequenceCheck.currentNonce;

            // capture the nonce as the "current nonce"
            //client.sigmaSequenceCheck.currentNonce = challengeResponseMessage.respHeader.sessionNonce;

            // Since this is the start of a new sequence, set the provisioningInProgress flag
            client.sigmaSequenceCheck.provisioningInProgress = true;

            log.Info("*********** Provisioning Request Valid - Sending Challenge Response");
            string challengeMsgJsonString = JsonConvert.SerializeObject(challengeResponseMessage);
            log.DebugFormat("\nChallenge Message JSON String: {0}\n\n", challengeMsgJsonString);

            return challengeResponseMessage;
        }

    }
}
