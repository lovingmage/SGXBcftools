//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Threading;
using System.Web;
using System.Web.Http;
using System.Web.Http.Results;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using Newtonsoft.Json;

using log4net;
using System.Reflection;
using SgxOptions;

namespace RaSpRef
{
    /// <summary>
    /// Thread class for processing Provisioning request and creating Challenge response
    /// </summary>
    class RemoteAttestationRequest
    {
        private Exception threadException = null;
        private HttpResponseException httpRE = null;
        private ChallengeResponse challengeResponse = null;
        private ClientTransaction mClient = null;

        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);

        /// <summary>
        /// Create a new Provision/Remote Attestation request
        /// Processes provision request and creates a Challenge response to send to a client
        /// </summary>
        /// <param name="data">Thread Data, input parameter (HttpRequestMessage) from the client</param>
        public void CreateNewRequest(object data)
        {
            challengeResponse = null;

            log.Debug("CreateNewRequest(.) started.");

            try
            {
                if (data == null)
                {
                    HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                    options.LogThrownException(e);
                    throw e;
                }

                HttpRequestMessage request = (HttpRequestMessage)data;

                var result = request.Content.ReadAsStringAsync();
                string jsonMsgRequest = result.Result;
                ProvisionRequestMessage pReceived = JsonConvert.DeserializeObject<ProvisionRequestMessage>(jsonMsgRequest);
                

                // Get client ID so we can track it
                string clientID = ClientDatabase.GetClientID(request, Constants.ProvisionStr);
                mClient = new ClientTransaction(clientID);
                mClient.sigmaSequenceCheck.currentNonce = pReceived.reqHeader.nonce;
                

                ProvisionRequest provRequest = new ProvisionRequest();
                ChallengeResponse tChallengeResponse = provRequest.ProcessProvisionRequest(request, mClient);

                // Add new client to request database only if successful
                if (!ClientDatabase.AddClient(mClient))
                {
                    HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Conflict);
                    options.LogThrownException(e);
                    throw e;
                }

                log.Info("\n ***** State: Starting Provision request for client: " + mClient.ID + "\n");

                // Update client state
                if (!mClient.sigmaSequenceCheck.UpdateState(Constants.SequenceState.Challenge))
                {
                    HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.PreconditionFailed);
                    options.LogThrownException(e);
                    throw e;
                }

                // Set Client State
                challengeResponse = tChallengeResponse;
            }
            catch (HttpResponseException re)
            {
                options.LogCaughtException(re);
                httpRE = re;
            }
            catch (Exception ex)
            {
                options.LogCaughtException(ex);
                threadException = ex;
            }
            finally
            {
                log.Debug("CreateNewRequest(.) returning.");
            }
        }

        // Thread Data accessors
        public HttpResponseException getHttpResponseException() { return httpRE; }
        public Exception getThreadException() { return threadException; }
        public ChallengeResponse getChallengeResponse() { return challengeResponse; }
        public ClientTransaction getWorkingClient() { return mClient; }
    };

    /// <summary>
    /// Thread Class for processing Message 0
    /// </summary>
    class Message0
    {
        private Exception threadException = null;
        private HttpResponseException httpRE = null;
        private ClientTransaction mClient = null;
        private M0ResponseMessage msg0Response = null;

        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);

        /// <summary>
        /// Process message 0
        /// </summary>
        /// <param name="data">Thread Data, input parameter (HttpRequestMessage) from the client</param>
        public void ProcessMessage(object data)
        {
            log.Debug("ProcessMessage(.) started.");

            try
            {
                if (data == null)
                {
                    HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                    options.LogThrownException(e);
                    throw e;
                }

                HttpRequestMessage request = (HttpRequestMessage)data;

                mClient = ClientDatabase.GetTransaction(request, Constants.msg0Str);
                if (mClient == null)
                {
                    Exception e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                    options.LogThrownException(e);
                    throw e;
                }

                // kill client wait thread so we don't time out. 
                mClient.killTimerThread();

                // NOTE: There is a potential race-condition where the client is removed from the database during the time that the cilent sends its response
                // Can choose to check to re-add the client here in that case


                log.Debug("\n ***** State: Starting Message 0 sequence for client: " + mClient.ID + "\n");

                Msg0 m0 = new Msg0();
                M0ResponseMessage m0Response = m0.ProcessMessage0(request, mClient.sigmaSequenceCheck);

                msg0Response = m0Response;

            }
            catch (HttpResponseException re)
            {
                options.LogCaughtException(re);
                httpRE = re;
            }
            catch (Exception ex)
            {
                options.LogCaughtException(ex);
                threadException = ex;
            }
            finally
            {
                log.Debug("ProcessMessage(.) returning.");
            }
        }

        // Thread Data accessors
        public HttpResponseException getHttpResponseException() { return httpRE; }
        public Exception getThreadException() { return threadException; }
        public ClientTransaction getWorkingClient() { return mClient; }
        public M0ResponseMessage getMessage0Response() { return msg0Response; }
    }

    /// <summary>
    /// Thread Class for processing Message 1 and creating Message 2
    /// </summary>
    class Message1Sequence2
    {
        private Exception threadException = null;
        private HttpResponseException httpRE = null;
        private M2ResponseMessage msg2Response = null;
        private ClientTransaction mClient = null;

        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);

        /// <summary>
        /// Process message 1 and create message 2 for the client
        /// </summary>
        /// <param name="data">Thread Data, input parameter (HttpRequestMessage) from the client</param>
        public void ProcessMessage(object data)
        {
            msg2Response = null;

            log.Debug("ProcessMessage(.) started.");

            try
            {
                if (data == null)
                {
                    HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                    options.LogThrownException(e);
                    throw e;
                }

                HttpRequestMessage request = (HttpRequestMessage)data;

                mClient = ClientDatabase.GetTransaction(request, Constants.msg1Str);
                if (mClient == null)
                {
                    Exception e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                    options.LogThrownException(e);
                    throw e;
                }

                // kill client wait thread so we don't time out. 
                mClient.killTimerThread();

                // NOTE: There is a potential race-condition where the client is removed from the database during the time that the cilent sends its response
                // Can choose to check to re-add the client here in that case


                log.Debug("\n ***** State: Starting Message 1/2 sequence for client: " + mClient.ID + "\n");

                Msg1 m1 = new Msg1();
                M2ResponseMessage m2Response = m1.ProcessMessage1(request, mClient.sigmaSequenceCheck);

                // Set Client State
                msg2Response = m2Response;
            }
            catch (HttpResponseException re)
            {
                options.LogCaughtException(re);
                httpRE = re;
            }
            catch (Exception ex)
            {
                options.LogCaughtException(ex);
                threadException = ex;
            }
            finally
            {
                log.Debug("ProcessMessage(.) returning.");
            }
        }

        // Thread Data accessors
        public HttpResponseException getHttpResponseException() { return httpRE; }
        public Exception getThreadException() { return threadException; }
        public M2ResponseMessage getMessage2() { return msg2Response; }
        public ClientTransaction getWorkingClient() { return mClient; }
    }

    /// <summary>
    /// Class to wait for a specific thread's timeout or completion
    /// </summary>
    class ThreadWait
    {
        private int timer = 0; // ms timer

        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);

        /// <summary>
        /// Check whether the thread has timed out or not
        /// </summary>
        /// <param name="t">Thread to monitor for timeout or completion</param>
        /// <returns>Boolean whether the thread timeout or not</returns>
        private static bool TimedOut()
        {
            int count = 0;
            while (count++ < (Constants.CLIENT_TIMEOUT))
            {
                Thread.Sleep(Constants.CLIENT_TIMEOUT * Constants.TICKS_PER_SECOND);
            }

            // We will always return True
            // Wait Thread should be killed from another thread to prevent timeout and removal of the client
            return true;
        }

        /// <summary>
        /// Wait for the client to send its response
        /// </summary>
        /// <param name="data"></param>
        public void Wait(object data)
        {
            try
            {
                if (data == null)
                {
                    Exception e = new System.ArgumentNullException("data");
                    options.LogThrownException(e);
                    throw e;
                }

                ClientTransaction client = (ClientTransaction)data;

                // We will wait until the timeout
                // During this time, if the client sends its response then the server shall kill this Wait Thread for the client transaction
                // to prevent removal of the client from the Client database
                bool timeOut = TimedOut();

                // If timed out, remove the client from the database
                if (timeOut)
                {
                    log.Debug("Client " + client.ID + " timed out");
                    ClientDatabase.RemoveTransaction(client);
                }
            }
            catch (Exception e)
            {
                if (e.Message.Contains("Thread was being aborted"))
                {
                    log.Debug("Client Thread was killed. ");
                }
                else
                {
                    log.Debug("ThreadWait: Wait failed. " + e.Message);
                }

            }

        }

        public int getTimeout() { return timer; }
    }

    /// <summary>
    /// Simulation Class for maintaining database of clients/devices for Remote Attestation
    /// </summary>
    static class ClientDatabase
    {
        private static ArrayList clients = new ArrayList();
        private static readonly object mLock = new Object();
        private static bool raInProgress = false;

        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);

        /// <summary>
        /// Waits for the specified thread to complete or timeout
        /// </summary>
        /// <param name="t">Thread to wait for timeout</param>
        /// <returns>Boolean whether the thread timed out or not</returns>
        private static async Task<bool> Wait(Thread t)
        {
            bool failed = true;

            if (t == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            failed = await Task.Run(() => TimedOut(t));
            return failed;
        }

        /// <summary>
        /// Check whether the thread has timed out or not
        /// </summary>
        /// <param name="t">Thread to monitor for timeout or completion</param>
        /// <returns>Boolean whether the thread timeout or not</returns>
        private static bool TimedOut(Thread t)
        {
            bool threadIsAlive = false;

            if (t == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            int count = 0;
            while (t.IsAlive && (count++ < (Constants.CLIENT_TIMEOUT)))
            {
                Thread.Sleep(Constants.CLIENT_TIMEOUT * Constants.TICKS_PER_SECOND);
            }

            if (t.IsAlive)
                threadIsAlive = true;

            return threadIsAlive;
        }

        /// <summary>
        /// Create new Client request
        /// </summary>
        /// <param name="request">Client Provisioning request</param>
        /// <returns>Challenge Response to client</returns>
        public static async Task<ChallengeResponse> NewRequest(HttpRequestMessage request)
        {
            if (request == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // Ignore new clients if transaction is already in progress
            if (raInProgress)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Conflict);
                options.LogThrownException(e);
                throw e;
            }

            log.Debug("NewRequest(.) started.");

            lock (mLock) { raInProgress = true; }

            RemoteAttestationRequest RARequest = new RemoteAttestationRequest();
            Thread oThread = new Thread(new ParameterizedThreadStart(RARequest.CreateNewRequest));
            oThread.Start(request);

            // wait for thread to finish
            bool failed = await Wait(oThread);

            //if WE timed out, return exception
            if (failed)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.GatewayTimeout);
                options.LogThrownException(e);
                throw e;
            }

            // if Completed (no timeout), get the result
            // check for exception/error
            if (RARequest.getHttpResponseException() != null)
            {
                HttpResponseException e = new HttpResponseException(RARequest.getHttpResponseException().Response);
                options.LogThrownException(e);
                throw e;
            }
            else if (RARequest.getThreadException() != null)
            {
                Exception e = new Exception("Provisioning request error", RARequest.getThreadException().InnerException);
                options.LogThrownException(e);
                throw e;
            }
            else if (RARequest.getChallengeResponse() == null)   // Unknown reason why it failed. Should never reach here/happen
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // start a new thread to track whether the client is taking too long
            ThreadWait tw = new ThreadWait();
            Thread waitThread = new Thread(new ParameterizedThreadStart(tw.Wait));
            RARequest.getWorkingClient().setTimerThread(waitThread);
            waitThread.Start(RARequest.getWorkingClient());


            log.Debug("NewRequest(.) returning.");
            // Return challenge to client
            return RARequest.getChallengeResponse();
        }

        /// <summary>
        /// Continue transaction for Message 0 sequence
        /// </summary>
        /// <param name="request">Client Message 0 response</param>
        /// <returns></returns>
        public static async Task<M0ResponseMessage> Message0(HttpRequestMessage request)
        {
            log.Debug("Message0(.) started.");

            if (request == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            Message0 msg0 = new Message0();
            Thread oThread = new Thread(new ParameterizedThreadStart(msg0.ProcessMessage));
            oThread.Start(request);

            // wait for thread to finish
            bool failed = await Wait(oThread);

            //if WE timed out, return exception
            if (failed)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.GatewayTimeout);
                options.LogThrownException(e);
                throw e;
            }

            // if Completed (no timeout), get the result
            // check for exception/error
            if (msg0.getHttpResponseException() != null)
            {
                HttpResponseException e = new HttpResponseException(msg0.getHttpResponseException().Response);
                options.LogThrownException(e);
                throw e;
            }
            else if (msg0.getThreadException() != null)
            {
                Exception e = new Exception("Msg0 request error", msg0.getThreadException().InnerException);
                options.LogThrownException(e);
                throw e;
            }
            else if (msg0.getMessage0Response() == null)   // Unknown reason why it failed. Should never reach here/happen
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }


            // start a new thread to track whether the client is taking too long
            ThreadWait tw = new ThreadWait();
            Thread waitThread = new Thread(new ParameterizedThreadStart(tw.Wait));
            msg0.getWorkingClient().setTimerThread(waitThread);
            waitThread.Start(msg0.getWorkingClient());

            log.Debug("Message0(.) returning.");
            return msg0.getMessage0Response();
        }

        /// <summary>
        /// Continue transaction for Message 1/2 sequence
        /// </summary>
        /// <param name="request">Client Message 1 response/2 request</param>
        /// <returns></returns>
        public static async Task<M2ResponseMessage> Message1(HttpRequestMessage request)
        {
            log.Debug("Message1(.) started.");

            if (request == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            Message1Sequence2 msg12 = new Message1Sequence2();
            Thread oThread = new Thread(new ParameterizedThreadStart(msg12.ProcessMessage));
            oThread.Start(request);

            // wait for thread to finish
            bool failed = await Wait(oThread);

            //if WE timed out, return exception
            if (failed)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.GatewayTimeout);
                options.LogThrownException(e);
                throw e;
            }

            // if Completed (no timeout), get the result
            // check for exception/error
            if (msg12.getHttpResponseException() != null)
            {
                HttpResponseException e = new HttpResponseException(msg12.getHttpResponseException().Response);
                options.LogThrownException(e);
                throw e;
            }
            else if (msg12.getThreadException() != null)
            {
                Exception e = new Exception("Provisioning request error", msg12.getThreadException().InnerException);
                options.LogThrownException(e);
                throw e;
            }
            else if (msg12.getMessage2() == null)   // Unknown reason why it failed. Should never reach here/happen
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // start a new thread to track whether the client is taking too long
            ThreadWait tw = new ThreadWait();
            Thread waitThread = new Thread(new ParameterizedThreadStart(tw.Wait));
            msg12.getWorkingClient().setTimerThread(waitThread);
            waitThread.Start(msg12.getWorkingClient());

            log.Debug("Message1(.) returning.");
            // Return challenge to client
            return msg12.getMessage2();
        }

        /// <summary>
        /// Continue transaction for Message 3/4 sequence
        /// </summary>
        /// <param name="request">Client Message 3 response/4 request</param>
        public static async Task<M4ResponseMessage> Message3(HttpRequestMessage request)
        {
            log.Debug("Message3(.) started.");

            if (request == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            M4ResponseMessage m4Response = null;

            try
            {
                ClientTransaction mClient = GetTransaction(request, Constants.msg3Str);
                if (mClient == null)
                {
                    HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                    options.LogThrownException(e);
                    throw e;
                }

                // kill client wait thread so we don't time out. 
                mClient.killTimerThread();

                // NOTE: There is a potential race-condition where the client is removed from the database during the time that the cilent sends its response
                // Can choose to check to re-add the client here in that case

                log.Info("\n ***** State: Starting Message 3/4 sequence for client: " + mClient.ID + "\n");

                Msg3 msg3 = new Msg3();
                m4Response = await msg3.ProcessMessage3(request, mClient.sigmaSequenceCheck);

                log.Debug("Message3(.) returning.");
            }
            catch (HttpResponseException)
            {
               throw;
            }
            catch (Exception e)
            {
                log.Debug("Error processing Message 3/4. " + e.Message);
            }

            // Return challenge to client
            return m4Response;
        }

        /// <summary>
        /// Retrieves the Client ID from the request
        /// </summary>
        /// <param name="request">Provisioning request</param>
        /// <returns>String ID of the requesting client</returns>
        public static string GetClientID(HttpRequestMessage request, string requestType)
        {
            log.DebugFormat("GetClientID({0}) started.", requestType);

            // Note: requestType==null case is handled in code farther down.

            if (request == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.BadRequest);
                options.LogThrownException(e);
                throw e;
            }

            // Need to get Client state (id) information
            var result = request.Content.ReadAsStringAsync();
            string jsonMsgRequest = result.Result;
            string ID = null;

            try
            {
                switch (requestType)
                {
                    case "Provision":
                        ProvisionRequestMessage pReceived = JsonConvert.DeserializeObject<ProvisionRequestMessage>(jsonMsgRequest);
                        ID = BitConverter.ToString(pReceived.reqHeader.nonce);
                        break;
                    case "Msg0":
                        M0RequestMessage m0Received = JsonConvert.DeserializeObject<M0RequestMessage>(jsonMsgRequest);
                        ID = BitConverter.ToString(m0Received.reqHeader.nonce);
                        break;
                    case "Msg1":
                        M1RequestMessage m1Received = JsonConvert.DeserializeObject<M1RequestMessage>(jsonMsgRequest);
                        ID = BitConverter.ToString(m1Received.reqHeader.nonce);
                        break;
                    case "Msg3":
                        M3RequestMessage m3Received = JsonConvert.DeserializeObject<M3RequestMessage>(jsonMsgRequest);
                        ID = BitConverter.ToString(m3Received.reqHeader.nonce);
                        break;
                    default:
                        {
                            HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                            options.LogThrownException(e);
                            throw e;
                        }
                }
            }
            catch (Exception msgError)
            {
                options.LogCaughtErrorException(msgError);
                log.DebugFormat("******* Message JSON Content Error: {0}\n", msgError);
                HttpResponseException newException = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(newException);
                throw newException;
            }

            if (ID != null)
                ID = ID.Replace("-", "").Trim();
            else
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            log.DebugFormat("GetClientID({0}) returning.", requestType);

            return ID;
        }

        /// <summary>
        /// Get Client Transaction associated with Request
        /// </summary>
        /// <param name="request">Client Provisioning Request</param>
        /// <param name="requestType">Message sequence value ID</param>
        /// <returns></returns>
        public static ClientTransaction GetTransaction(HttpRequestMessage request, string requestType)
        {
            log.DebugFormat("GetTransaction({0}) started.", requestType);

            // Note: both request==null and requestType==null cases are handled below, in GetClientID.

            string clientID = GetClientID(request, requestType);
            ClientTransaction client = FindClientTransaction(clientID);

            if (client == null)
                log.Debug("Client " + clientID + " not found");

            log.DebugFormat("GetTransaction({0}) returning.", requestType);
            return client;
        }

        /// <summary>
        /// Determines whether the specified client transaction already exists or not
        /// </summary>
        /// <param name="clientID">ID of the transaction</param>
        /// <returns>Boolean whether the transaction exists or not</returns>
        private static bool ContainsTransaction(string clientID)
        {
            log.DebugFormat("ContainsTransaction({0}) started.", clientID);
            if (clientID == null || clients == null)
            {
                log.DebugFormat("ContainsTransaction({0}) returning false because of null inputs.", clientID);
                return false;
            }

            for (int i = 0; i < clients.Count; i++)
            {
                if (((ClientTransaction)clients[i]).ID == clientID)
                {
                    log.DebugFormat("GetTransaction({0}) returning true.", clientID);
                    return true;
                }
            }

            log.DebugFormat("GetTransaction({0}) returning false.", clientID);
            return false;
        }

        /// <summary>
        /// Find the Client Transaction in the databse of clients
        /// </summary>
        /// <param name="clientID">ID of the client to find</param>
        /// <returns>Boolean whether the operation succeeded or not</returns>
        private static ClientTransaction FindClientTransaction(string clientID)
        {
            log.DebugFormat("FindClientTransaction({0}) started.", clientID);

            try
            {
                if (clientID == null || clients == null)
                {
                    log.DebugFormat("FindClientTransaction({0}) returning <null> because of null inputs.", clientID);
                    return null;
                }

                for (int i = 0; i < clients.Count; i++)
                {
                    if (((ClientTransaction)clients[i]).ID == clientID)
                    {
                        log.DebugFormat("FindClientTransaction({0}) returning {1}.", clientID, ((ClientTransaction)clients[i]).ID);
                        return (ClientTransaction)clients[i];
                    }
                }
            }
            catch (Exception e)
            {
                options.LogCaughtException(e);
                log.Debug("Failed searching for client transaction. " + e.Message);
                HttpResponseException newException = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(newException);
                throw newException;
            }

            log.DebugFormat("FindClientTransaction({0}) returning <null>.", clientID);
            return null;
        }

        /// <summary>
        /// Finds the index of the specified Client Transaction in the client database
        /// </summary>
        /// <param name="clientID">ID of the client to find</param>
        /// <returns>Integer index value of the client</returns>
        private static int FindIndexOfClientTransaction(string clientID)
        {
            log.DebugFormat("FindIndexOfClientTransaction({0}) started.", clientID);

            // invalid/doesn't exist
            if (clientID == null || clients == null)
            {
                log.DebugFormat("FindClientTransaction({0}) returning -1 because of null inputs.", clientID);
                return -1;
            }

            // Find the client
            for (int i = 0; i < clients.Count; i++)
            {
                if (((ClientTransaction)clients[i]).ID.Equals(clientID))
                {
                    log.DebugFormat("FindClientTransaction({0}) returning {1}.", clientID, i);
                    return i;
                }
            }

            // doesn't exist
            log.DebugFormat("FindClientTransaction({0}) returning -1 because it doesn't exist.", clientID);
            return -1;
        }


        /// <summary>
        /// Add client to transaction database, only if it doesn't already exist
        /// </summary>
        /// <param name="clientID">ID of the client</param>
        public static bool AddClient(ClientTransaction ct)
        {
            // This if-else is unnecessary because the debug log will print "null" if
            // ct.ID==NULL, but we do it anyway just to make klocwork happy.
            if (ct != null)
            {
                log.DebugFormat("AddClient({0}) started (before lock).", ct.ID);
            }
            else
            {
                log.Debug("AddClient(<null>) started (before lock).");
            }

            if (ct == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            lock (mLock)
            {
                log.DebugFormat("AddClient({0}) started (after lock).", ct.ID);
                if (FindClientTransaction(ct.ID) != null)
                {
                    log.Debug("Client " + ct.ID + " transaction already exists.");
                    log.DebugFormat("AddClient({0}) returning false because it already exists.", ct.ID);
                    return false;
                }

                clients.Add(ct);

                if (!ContainsTransaction(ct.ID))
                {
                    log.Debug("Failed to add " + ct.ID + " to the transaction database");
                    HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                    options.LogThrownException(e);
                    throw e;
                }

                log.Debug("Added " + ct.ID + " to the transaction database.");
            }

            log.DebugFormat("AddClient({0}) returning true.", ct.ID);
            return true;
        }

        /// <summary>
        /// Removes the client transaction from the client database
        /// </summary>
        /// <param name="request">Client request</param>
        /// <param name="requestType">Message sequence value</param>
        /// <returns>Boolean whether the operation succeeded or not</returns>
        public static bool RemoveTransaction(HttpRequestMessage request, string requestType)
        {
            if (request == null || String.IsNullOrEmpty(requestType))
                return false;

            // Note:  requestType==null case handled within GetTransaction

            log.DebugFormat("RemoveTransaction({0}) started.", requestType);

            log.Debug("Removing Client Transaction from database");
            ClientTransaction client = GetTransaction(request, requestType);

            bool removed = RemoveClient(client);

            // Remove transaction lock
            lock (mLock) { raInProgress = false; }

            log.Debug("Active transactions: " + NumberOfClients());

            log.DebugFormat("RemoveTransaction({0}) returning (1).", requestType, removed);
            return removed;
        }

        public static bool RemoveTransaction(ClientTransaction clientT)
        {
            if (clientT == null)
                return false;

            log.Debug("Removing Client Transaction from database");

            bool removed = RemoveClient(clientT);

            lock (mLock) { raInProgress = false; }

            log.Debug("Active transactions: " + NumberOfClients());
            return removed;
        }

        /// <summary>
        /// Removes the specified client from the database of transactions
        /// </summary>
        /// <param name="ct">Client Transaction to remove from database</param>
        /// <returns>Boolean whether the operation succeeded or not</returns>
        private static bool RemoveClient(ClientTransaction client)
        {
            if (client == null)
                return false;

            log.DebugFormat("RemoveClient({0}) started.", client.ID);

            try
            {
                lock (mLock)
                {
                    log.Info("Removing Client: " + client.ID);
                    log.Info("***************************************************************");
                    // remove
                    int index = FindIndexOfClientTransaction(client.ID);
                    if (index < 0)
                        return true;

                    clients.RemoveAt(index);
                    //client.killTimerThread();

                    // ensure removed
                    index = FindIndexOfClientTransaction(client.ID);
                    if (index == -1)
                        return true;
                }
            }
            catch (Exception e)
            {
                options.LogCaughtErrorException(e);
                log.Debug("Error while removing client transaction from database. " + e.Message);
            }

            log.DebugFormat("RemoveClient({0}) returning false.", client.ID);
            return false;
        }

        /// <summary>
        /// Gets the number of active client transactions
        /// </summary>
        /// <returns>Integer number of active client sessions</returns>
        public static int NumberOfClients()
        {
            if (clients == null)
                return 0;

            return clients.Count;
        }

    }
}
