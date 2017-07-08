//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

//
//
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
using System.Web;
using System.Threading.Tasks;
using System.ComponentModel;
using log4net;
using System.Reflection;
using SgxOptions;

namespace RaSpRef
{
    public class SpMsgsController : ApiController
    {
        // NOTE: TLS/https for the shared client connection with IAS can be
        // enabled on the IAS simulator by setting the "enable https" properties
        // flag to "True" on the simulator project's Properties window.


        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // NOTE: In order to create a pseudo sigma session with HTTP, this controller implements a very simple state 
        // machine with guard conditions on action result triggers for each state transition.   
        // Processing errors or any messages received out of sequence should reinitialize the state machine.
        // 
        // Start --> provisioningInProgress --> m1Received --> m3Recieved
        //  ^----error--------'                   |              |    |
        //  ^------------------error--------------'              |    |
        //  ^--------------------------error---------------------'    |
        //  ^-----------------------------sequence complete-----------'
        //
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);

        // api/SpMsgs/ProvisioningRequest
        [HttpPost]
        [Route("api/SpMsgs/ProvisioningRequest")]
        public async Task<IHttpActionResult> ProvisioningRequest()
        {
            log.Debug("ProvisioningRequest(.) started.");

            bool error = false;
            HttpStatusCode errorCode = System.Net.HttpStatusCode.InternalServerError;
            ChallengeResponse challengeResponse = null;

            try
            {
                challengeResponse = await ClientDatabase.NewRequest(this.Request);
            }
            catch (WebException we)
            {
                error = true;
                HttpWebResponse WebResponse = we.Response as HttpWebResponse;
                log.Debug("Web Exception in Provisioning Request: " + we.Message);
                errorCode = (HttpStatusCode)WebResponse.StatusCode;
            }
            catch (HttpResponseException re)
            {
                error = true;
                log.Debug("HttpResponseException in Provisioning Request: " + re.Message);
                errorCode = (HttpStatusCode)re.Response.StatusCode;
            }
            catch (Exception e)
            {
                error = true;
                log.Debug("Error occurred processing provision request. " + e.Message);
                errorCode = System.Net.HttpStatusCode.InternalServerError;
            }

            // Return response to client
            if (error)
            {
                log.DebugFormat("ProvisioningRequest(.) returning HTTP status code {0}.", errorCode);
                try
                {
                    if (errorCode != (HttpStatusCode)System.Net.HttpStatusCode.Conflict)
                        ClientDatabase.RemoveTransaction(this.Request, Constants.ProvisionStr);
                }
                catch (Exception e)  // This catches HttpResponseException also, which is what we want here
                {
                    log.Debug("Exception in provision request while error cleanup RemoveTransaction(): " + e.Message);
                }
                return StatusCode(errorCode);
            }
            else
            {
                log.Debug("ProvisioningRequest(.) returning HTTP status success.");
                return Json(challengeResponse);
            }
        }

        // POST: api/SpMsgs/Msg0
        [HttpPost]
        [Route("api/SpMsgs/Msg0")]
        public async Task<IHttpActionResult> Msg0()
        {
            log.Debug("Msg0(.) started.");

            bool error = false;
            HttpStatusCode errorCode = System.Net.HttpStatusCode.InternalServerError;
            M0ResponseMessage m0Response = null;

            try
            {
                m0Response = await ClientDatabase.Message0(this.Request);
            }

            catch (WebException we)
            {
                error = true;
                log.Debug("Web Exception in Message 0: " + we.Message);
                HttpWebResponse WebResponse = we.Response as HttpWebResponse;
                errorCode = (HttpStatusCode)WebResponse.StatusCode;
            }
            catch (HttpResponseException re)
            {
                error = true;
                log.Debug("HttpResponseException in Message 0: " + re.Message);
                errorCode = (HttpStatusCode)re.Response.StatusCode;
            }
            catch (Exception e)
            {
                error = true;
                log.Debug("******* M0 Content Error");
                log.Debug("Error: " + e.Message);
                errorCode = System.Net.HttpStatusCode.InternalServerError;
            }

            // Return response to client
            if (error)
            {
                log.DebugFormat("Msg0(.) returning HTTP status code {0}.", errorCode);
                try
                {
                    ClientDatabase.RemoveTransaction(this.Request, Constants.msg0Str);
                }
                catch (Exception e)  // This catches HttpResponseException also, which is what we want here
                {
                    log.Debug("Exception in Message 0 while error cleanup RemoveTransaction(): " + e.Message);
                }
                return StatusCode(errorCode);
            }
            log.Debug("Msg0(.) success - Accepted HTTP response.");
            return Json(m0Response);
        }

        // POST: api/SpMsgs/Msg1
        [HttpPost]
        [Route("api/SpMsgs/Msg1")]
        public async Task<IHttpActionResult> Msg1()
        {
            log.Debug("Msg1(.) started.");

            bool error = false;
            HttpStatusCode errorCode = System.Net.HttpStatusCode.InternalServerError;
            M2ResponseMessage m2Response = null;

            try
            {
                m2Response = await ClientDatabase.Message1(this.Request);
            }
            catch (WebException we)
            {
                error = true;
                log.Debug("Web Exception in Provisioning Request: " + we.Message);
                HttpWebResponse WebResponse = we.Response as HttpWebResponse;
                errorCode = (HttpStatusCode)WebResponse.StatusCode;
            }
            catch (HttpResponseException re)
            {
                error = true;
                log.Debug("HttpResponseException in Message 1/2: " + re.Message);
                errorCode = (HttpStatusCode)re.Response.StatusCode;
            }
            catch (Exception e)
            {
                error = true;
                log.Debug("******* M1 Content Error");
                log.Debug("Error: " + e.Message);
                errorCode = System.Net.HttpStatusCode.InternalServerError;
            }

            // Return response to client
            if (error)
            {
                log.DebugFormat("Msg1(.) returning HTTP status code {0}.", errorCode);
                try
                {
                    ClientDatabase.RemoveTransaction(this.Request, Constants.msg1Str);
                }
                catch (Exception e)  // This catches HttpResponseException also, which is what we want here
                {
                    log.Debug("Exception in Message 1/2 while error cleanup RemoveTransaction(): " + e.Message);
                }
                return StatusCode(errorCode);
            }
            else
            {
                log.Debug("Msg1(.) returning HTTP status success.");
                return Json(m2Response);
            }
        }
        

        // POST: api/SpMsgs/Msg3
        [HttpPost]
        [Route("api/SpMsgs/Msg3")] 
        public async Task<IHttpActionResult> Msg3()
        {
            log.Debug("SpSequenceCheck(.) started.");

            bool error = false;
            HttpStatusCode errorCode = System.Net.HttpStatusCode.InternalServerError;
            M4ResponseMessage m4Response = null;

            try
            {
                m4Response = await ClientDatabase.Message3(this.Request);
            }
            catch (WebException we)
            {
                error = true;
                log.Debug("Web Exception in Provisioning Request: " + we.Message);
                HttpWebResponse webResponse = we.Response as HttpWebResponse;
                errorCode = (HttpStatusCode)webResponse.StatusCode;
            }
            catch (HttpResponseException re)
            {
                error = true;
                log.Debug("HttpResponseException in Message 3/4: " + re.Message);
                errorCode = (HttpStatusCode)re.Response.StatusCode;
            }
            catch (Exception e)
            {
                error = true;
                log.Debug("Error occurred processing Message 3 or 4. " + e.Message);
                errorCode = System.Net.HttpStatusCode.InternalServerError;
            }

            // always cleanup database on Message 4
            try
            {
                ClientDatabase.RemoveTransaction(this.Request, Constants.msg3Str);
            }
            catch (HttpResponseException re)
            {
                log.Debug("HttpResponseException in Message 3/4 RemoveTransaction: " + re.Message);
                if (!error)
                {
                    error = true;
                    errorCode = (HttpStatusCode)re.Response.StatusCode;
                }
            }
            catch (Exception e)
            {
                log.Debug("Error occurred processing Message 3 or 4 RemoveTransaction: " + e.Message);
                if (!error)
                {
                    error = true;
                    errorCode = System.Net.HttpStatusCode.InternalServerError;
                }
            }

            if (error)
            {
                log.DebugFormat("Msg3(.) returning HTTP status code {0}.", errorCode);
                return StatusCode(errorCode);
            }
            else
            {
                log.Debug("Msg3(.) returning HTTP status success.");
                return Json(m4Response);
            }
        }

    }
}
