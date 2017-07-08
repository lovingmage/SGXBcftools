//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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
    class Msg2Builder
    {
        #region DiffieHellmanVariables
        private byte[] _gbXLittleEndian = new byte[Constants.GaGbLen];
        private byte[] _gbYLittleEndian = new byte[Constants.GaGbLen];
        private String _gidBaString = "";
        bool initialized = false;
        byte[] _sigSPXLittleEndian;
        byte[] _sigSPYLittleEndian;
        byte[] _cMACsmk;
        #endregion

        // Set up a new message 2 message object.
        private M2ResponseMessage msg2 = new M2ResponseMessage();
        private BuildMessage bMessage = new BuildMessage();

        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);

        /// <summary>
        /// Build Message 2
        /// </summary>
        /// <param name="sigmaSequenceCheck">Service Provider Sequence (State) Check</param>
        /// <param name="m1Received">Message 1</param>
        /// <returns>Message 2 Repsonse to Client</returns>
        public M2ResponseMessage BuildMessage2(SpSequenceCheck sigmaSequenceCheck, M1RequestMessage m1Received,
            String gidBaString, byte[] gbXLittleEndian, byte[] gbYLittleEndian, byte[] sigSPXLittleEndian, byte[] sigSPYLittleEndian, byte[] cMACsmk)
        {
            log.Debug("BuildMessage2(.) started.");

            if (sigmaSequenceCheck == null || m1Received == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // Update Client state
            if (!sigmaSequenceCheck.UpdateState(Constants.SequenceState.Msg2))
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.PreconditionFailed);
                options.LogThrownException(e);
                throw e;
            }

            SetDiffieHellmanExchange(gidBaString, gbXLittleEndian, gbYLittleEndian, sigSPXLittleEndian, sigSPYLittleEndian, cMACsmk);

            // Check that  Diffie Hellman values are initialized
            if (!initialized)
                return null;

            log.Debug("Building message 2");
            
            if (SpStartup.iasConnectionMgr.UseIAS)
            {
                // Connect to IAS for Signature Revocation List
                BuildIASMessage2(sigmaSequenceCheck);
            }
            else
            {
                // Simulate IAS
                // For testing the SGX client connection only, override the IAS connection settings by setting "UseIAS" to false.
                // This setting should be temporary, and once the SGX messaging is working, set "UseIAS" to true.
                BuildNonIasMessage2(sigmaSequenceCheck);
            }

            log.Debug("BuildMessage2(.) returning.");
            return msg2;
        }

        /// <summary>
        /// Build Message 2 response for Non-IAS Connection; Used for Debug only
        /// </summary>
        /// <returns>Message 2 response to client</returns>
        private void BuildNonIasMessage2(SpSequenceCheck sigmaSequenceCheck)
        {

            // NOTE: This debugging path bypasses the IAS connection and ignores the SigRL.
            // This path is intended for temporary testing of the sigma messaging with the SGX client.
            // 
            // Production Server MUST use the IAS connection for a secure check of the enclave.
            // Update the M2 response fields and add a null SigRL for this debug path.
            // m2 = gb||SPID||Quote Type||SigSP(gb||ga)||MACsmk(gb||SPID||Type||SigSP(gb||ga));SigRL

            log.Debug("BuildNonIasMessage2(.) started.");

            if (sigmaSequenceCheck == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            bMessage.buildM2Response(out msg2);
            msg2.respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrIasGetSuccess);
            if (SpStartup.iasConnectionMgr.SPID.Length != 16)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.PreconditionFailed);
                options.LogThrownException(e);
                throw e;
            }

            // We need endianness agreement between client and server for sending each message term
            msg2.respMsg2Body.gbX = _gbXLittleEndian;
            msg2.respMsg2Body.gbY = _gbYLittleEndian;
            msg2.respMsg2Body.spId = SpStartup.iasConnectionMgr.SPID;
            msg2.respMsg2Body.sigLinkType = Constants.sltype;
            msg2.respMsg2Body.kdfId = Constants.kdfId;
            msg2.respMsg2Body.sigSpX = _sigSPXLittleEndian;
            msg2.respMsg2Body.sigSpY = _sigSPYLittleEndian;
            msg2.respMsg2Body.cmacsmk = _cMACsmk;

            // Since this debug path does not include a dialog with the IAS server,
            // there is no sigRL to retrieve. 
            // Build the sigRL message fields to reflect a sigRL of zero length.
            msg2.respMsg2Body.sigrlSize = MsgInitValues.DS_ZERO_BA4;
            msg2.respMsg2Body.sigRl = null;
            msg2.respHeader.msgLength = BitConverter.GetBytes((UInt32)msg2.GetMsgString().Length / 2);

            msg2.respHeader.sessionNonce = sigmaSequenceCheck.currentNonce;
            sigmaSequenceCheck.m1Received = true;

            string msg2JsonString = JsonConvert.SerializeObject(msg2);
            log.Info("*********** Msg1 Processing Complete - Sending Msg2");
            log.DebugFormat("Msg2 JSON String: {0}", msg2JsonString);
            log.DebugFormat("Msg2 16bit encoded string: {0}", msg2.GetMsgString());

            log.Debug("BuildNonIasMessage2(.) returning.");
        }

        /// <summary>
        /// Builds Message 2 using connection IAS
        /// </summary>
        /// <param name="sigmaSequenceCheck">Service Provider Sequence (state) check</param>
        /// <returns>Boolean whether the message creation was successful or not</returns>
        private Boolean BuildIASMessage2(SpSequenceCheck sigmaSequenceCheck)
        {
            string iasGetRequestString = null;

            log.Debug("BuildIASMessage2(.) started.");

            if (sigmaSequenceCheck == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            try
            {
                log.Debug("Using IAS");

                // Get URI to IAS 
                iasGetRequestString = SpStartup.iasConnectionMgr.iasUri + Constants.SigRLUri + _gidBaString;
                log.DebugFormat("Sending IAS GET Request using: {0}", iasGetRequestString);
            }
            catch (Exception getReqError)
            {
                options.LogCaughtErrorException(getReqError);

                log.Debug("Failed to get IAS Uri");

                // Copy error msg2 object to that which will be returned
                msg2 = CreateErrorMessage(getReqError);
                log.Debug("BuildIASMessage2(.) returning false.");
                return false;
            }

            try
            {
                // Check connectivity with IAS Server

                // Use the received m1 as a trigger to check for a sigRL
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                int retryCount = Constants.retryCount;
                HttpResponseMessage iasSigRlResponse = null;
                byte[] internalError = BitConverter.GetBytes((UInt32)enStatusCodes.raErrIasInternal);
                while (retryCount-- > 0)
                {

                    // Instantiate an HttResponseMessage object for the GET SigRL request with IAS.
                    var iasResult = sigmaSequenceCheck.iasClient.GetAsync(iasGetRequestString);
                    iasSigRlResponse = iasResult.Result;

                    // retry if we have an internal IAS error
                    if (iasSigRlResponse.StatusCode == HttpStatusCode.InternalServerError)
                        log.Debug("IAS error. Retrying...");
                    else
                        break;
                }

                // Check for failure on max attempts
                if (iasSigRlResponse.StatusCode == HttpStatusCode.InternalServerError)
                    throw new HttpResponseException(System.Net.HttpStatusCode.ServiceUnavailable);

                log.DebugFormat("******* IAS GET Response:  {0}", iasSigRlResponse.ReasonPhrase);
                var result = iasSigRlResponse.Content.ReadAsStringAsync();   // Signature Revocation List response from IAS
                string nnSigRlInput = result.Result;

                Boolean error = false;
                String errorReason = "Unknown Error";

                // Check Signature Revocation List status code
                switch (iasSigRlResponse.StatusCode)
                {
                    case HttpStatusCode.OK:
                        {
                            // With a successful IAS GET Response, finish building Msg2.
                            // Decode the sigRl from the IAS response and populate the M2 sigRL fields,
                            // store GID, and ga until the Sigma sequence is complete.
                            //
                            // Update the M2 response fields for a successful response and add the SigRL
                            // if the IAS server returned a non-null list.
                            //                          
                            // m2 = gb||SPID||Quote Type||SigSP(gb||ga)||MACsmk(gb||SPID||Type||SigSP(gb||ga));SigRL

                            bMessage.buildM2Response(out msg2);
                            msg2.respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrIasGetSuccess);

                            // We need endianness agreement between client and server for sending each message term. 
                            // This protocol implementation assumes LittleEndian between client and server.
                            msg2.respMsg2Body.gbX = _gbXLittleEndian;
                            msg2.respMsg2Body.gbY = _gbYLittleEndian;
                            msg2.respMsg2Body.spId = SpStartup.iasConnectionMgr.SPID;
                            msg2.respMsg2Body.sigLinkType = Constants.sltype;
                            msg2.respMsg2Body.kdfId = Constants.kdfId;
                            msg2.respMsg2Body.sigSpX = _sigSPXLittleEndian;
                            msg2.respMsg2Body.sigSpY = _sigSPYLittleEndian;
                            msg2.respMsg2Body.cmacsmk = _cMACsmk;

                            // Check for Null Signature Revocation List
                            if (iasSigRlResponse.Content.Headers.ContentLength == 0)
                            {
                                msg2.respMsg2Body.sigrlSize = MsgInitValues.DS_ZERO_BA4;
                                msg2.respMsg2Body.sigRl = null;
                            }
                            else
                            {
                                // The SigRL can have a variable content length; so just accept the length from 
                                // the IAS response as long as the size fits a predetermined practical size limit.
                                if (iasSigRlResponse.Content.Headers.ContentLength <= MsgFieldLimits.UINT32_PRACTICAL_SIZE_LIMIT)
                                {
                                    msg2.respMsg2Body.sigrlSize = BitConverter.GetBytes((UInt32)iasSigRlResponse.Content.Headers.ContentLength);
                                    // Parse non-null content and test with a non-null SigRL if IAS can deliver base64 encoded content similar to:
                                    // AAIADgAAAAEAAAABAAAAAHPUffSvHLYJc1GcvVLdoHZSfTo1qY7YqCtL3lqnWz4WI/JeLqDkU7eXpm5tdn1PoXEULgOSPJA8DJigmj4rBEU=
                                    // NOTE: testing was done with simulated content as shown above.
                                    //////////////////////////////////////////////////////////
                                    byte[] nnSigRlBa = null;
                                    nnSigRlBa = Convert.FromBase64String(nnSigRlInput);
                                    msg2.respMsg2Body.sigrlSize = BitConverter.GetBytes((UInt32)nnSigRlBa.Length);  // Report the length of the actual SigRl data, not the base64 string
                                    msg2.respMsg2Body.sigRl = nnSigRlBa;
                                    //////////////////////////////////////////////////////////
                                }
                                else //Signature Revocation List is too big; May allow for larger sizes
                                {
                                    log.Debug("****** Error SigRL Exceeds Internal Limit ******");
                                    break;
                                }
                            }

                            // Update the length field in the message header
                            msg2.respHeader.msgLength = BitConverter.GetBytes((UInt32)msg2.GetMsgString().Length / 2);
                            // Update the state machine
                            // Capture the message nonce as the "current nonce"
                            msg2.respHeader.sessionNonce = sigmaSequenceCheck.currentNonce;
                            // Complete the state transition
                            sigmaSequenceCheck.m1Received = true;
                            string msg2JsonString = JsonConvert.SerializeObject(msg2);
                            log.Debug("*********** Msg1 Processing Complete - Sending Msg2");
                            log.DebugFormat("{0}", msg2JsonString);
                            break;
                        }
                    case HttpStatusCode.Unauthorized:
                        {
                            msg2.respHeader.respStatus = BitConverter.GetBytes((UInt32)RaSpRef.enStatusCodes.raErrIasUnauth);
                            errorReason = "****** Sending Msg2 \"Unauthorized\" Error Response";
                            break;
                        }
                    case HttpStatusCode.NotFound:
                        {
                            msg2.respHeader.respStatus = BitConverter.GetBytes((UInt32)RaSpRef.enStatusCodes.raErrIasNotFound);
                            errorReason = "****** Sending Msg2 \"Not Found\" Error Response";
                            break;
                        }
                    case HttpStatusCode.InternalServerError:    // This should never be executed
                        {
                            msg2.respHeader.respStatus = BitConverter.GetBytes((UInt32)RaSpRef.enStatusCodes.raErrIasInternal);
                            errorReason = "****** Sending Msg2 \"Internal Server Error\" Error Response";
                            break;
                        }
                    default:
                        {
                            msg2.respHeader.respStatus = BitConverter.GetBytes((UInt32)RaSpRef.enStatusCodes.raErrUnknown);
                            errorReason = "****** Sending Msg2 \"Unknown\" Error Response";
                            break;
                        }
                }

                // Print messages on error
                if (error)
                {
                    string msg2ErrorMsgString = msg2.GetMsgString();
                    msg2.respHeader.protocolVer = MsgInitValues.PROTOCOL;
                    msg2.respHeader.msgLength = BitConverter.GetBytes((UInt32)msg2ErrorMsgString.Length / 2);
                    string msg2ErrorMsgJsonString = JsonConvert.SerializeObject(msg2);

                    log.Debug(errorReason);
                    log.Debug("SigRL Response Status: " + BitConverter.ToString(msg2.respHeader.respStatus));
                    log.DebugFormat("{0}", msg2ErrorMsgJsonString);
                }

                iasSigRlResponse.Dispose();
            }
            catch (HttpResponseException)
            {
                // This catch block is to prevent subsequent catch blocks from catching HttpResponseExceptions.
                // Because we are using Visual Studio 2012, we are limited to an older version of the C#
                // language that does not support exception filters. When C# 6 is available to us, it may
                // be decided that exception filters are a better solution than this catch block.
                throw;
            }
            catch (Exception getReqError)
            {
                // Copy error msg2 object to that which will be returned
                msg2 = CreateErrorMessage(getReqError);
                log.Debug("BuildIASMessage2(.) returning false.");
                return false;
            }

            // Success
            log.Debug("BuildIASMessage2(.) returning true.");
            return true;
        }

        /// <summary>
        /// Create a Message 2 for error condition
        /// </summary>
        /// <returns>Message 2 error message</returns>
        private M2ResponseMessage CreateErrorMessage(Exception errorMessage)
        {
            log.Debug("CreateErrorMessage(.) started.");

            if (errorMessage == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // Handle the case where there is no HTTP response from IAS
            // There was a problem with the GET SigRL request - respond to Msg1 and abort the sequence.
            log.Debug("\n****** IAS GET Failure - aborting message sequence");
            log.DebugFormat("**** IAS Error **** \n{0}", errorMessage);
            log.Debug("******");
            // Create an "Empty" Msg2 instance to return error information 
            M2ResponseMessage msg2ErrorMsg = new M2ResponseMessage();
            string msg2ErrorMsgString = msg2ErrorMsg.GetMsgString();

            // NOTE: Additional HTTP errors and exceptions should be handled here
            string exceptionString = errorMessage.InnerException.Message;
            switch (exceptionString)
            {
                case "An error occurred while sending the request.":
                    msg2ErrorMsg.respHeader.respStatus = BitConverter.GetBytes((UInt32)RaSpRef.enStatusCodes.raErrIasUnknown);
                    break;
                default:
                    msg2ErrorMsg.respHeader.respStatus = BitConverter.GetBytes((UInt32)RaSpRef.enStatusCodes.raErrUnknown);
                    break;
            }

            // Update the length field even though it should be the same as the default length.
            msg2ErrorMsg.respHeader.msgLength = BitConverter.GetBytes((UInt32)msg2ErrorMsgString.Length / 2);
            string msg2ErrorMsgJsonString = JsonConvert.SerializeObject(msg2ErrorMsg);
            log.Debug("****** Sending Msg2 Error Response");
            log.Debug("SigRL Response Status: " + BitConverter.ToString(msg2.respHeader.respStatus));
            log.Debug(msg2ErrorMsgJsonString);

            log.Debug("M2ResponseMessage(.) returning.");
            return msg2ErrorMsg;
        }

        /// <summary>
        /// Sets variables needed for Diffie Hellman exchange variable calculation
        /// </summary>
        /// <param name="gidBaString"></param>
        /// <param name="gbXLittleEndian"></param>
        /// <param name="gbYLittleEndian"></param>
        /// <param name="sigSPXLittleEndian"></param>
        /// <param name="sigSPYLittleEndian"></param>
        /// <param name="cMACsmk"></param>
        private void SetDiffieHellmanExchange(String gidBaString, byte[] gbXLittleEndian, byte[] gbYLittleEndian, byte[] sigSPXLittleEndian, byte[] sigSPYLittleEndian, byte[] cMACsmk)
        {
            log.Debug("SetDiffieHellmanExchange(......) started.");

            if (gidBaString == null || gbXLittleEndian == null || gbYLittleEndian == null || sigSPXLittleEndian == null || sigSPYLittleEndian == null || cMACsmk == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            _gidBaString = gidBaString;
            _gbXLittleEndian = gbXLittleEndian;
            _gbYLittleEndian = gbYLittleEndian;
            _sigSPXLittleEndian = sigSPXLittleEndian;
            _sigSPYLittleEndian = sigSPYLittleEndian;
            _cMACsmk = cMACsmk;

            initialized = true;

            log.Debug("SetDiffieHellmanExchange(......) returning.");
        }

    }
}
