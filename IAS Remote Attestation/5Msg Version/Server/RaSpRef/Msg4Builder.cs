//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IppDotNetWrapper;
using System.Web.Http;
using System.Web.Http.Results;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using log4net;
using System.Reflection;
using SgxOptions;
using System.IO;

namespace RaSpRef
{
    class Msg4Builder
    {



        // Attestation Status codes mapped from the IAS Backend Attestation Evidence Response.
        public enum enAttestationStatusCodes : uint
        {
            raAttestationErrOK = 0x00,                // 00, "OK", Attestation Success
            raAttestationErrSigInvalid = 0x01,        // 01, "SIGNATURE_INVALID" Invalid quote signature - do not trust
            raAttestationErrGrpRevoked = 0x02,        // 02, "GROUP_REVOKED" EPID group revoked - do not trust
            raAttestationErrSigRevoked = 0x03,        // 03, "SIGNATURE_REVOKED" EPID Private Key revoked by signature - do not trust
            raAttestationErrKeyRevoked = 0x04,        // 04, "KEY_REVOKED" EPID Private Key directly revoked - do not trust
            raAttestationErrSigRlVerMismatch = 0x05,  // 05, "SIGRL_VERSION_MISMATCH" Enclave SigRL Version Mismatch - do not trust
            raAttestationErrGrpOutOfDate = 0x06,      // 06, "GROUP_OUT_OF_DATE" TCB platform level is out of date - do not trust or trust depending on policy
            raAttestationErrUnknown = 0x07            // 07, Unhandled IAS attestation status - do not trust 
        }

        public enum enEnclaveTrustStatusCodes : uint
        {
            raTrustAll = 0x00,                         // Server trusts client enclave (and PSE if it is present)
            raTrustEnclaveOnly = 0x01,                 // Server trusts client enclave but doesn't trust PSE
            raTrustNone = 0x02,                        // Server doesn't trust client enclave (or PSE)
            raTrustRetry = 0x03,                       // Server doesn't trust client enclave (or PSE) but may if the client retries attestation
            raTrustCheckPIB = 0x80                     // PIB is included in this message

        }

        public enum enPSETrustStatusCodes : uint
        {
            raPSETrusted = 0x00,                       // Server trusts PSE
            raPSENotTrusted = 0x01,                    // Server does not trust PSE
            raPSETrusted_SendPIB = 0x02,               // Server trusts PSE and will send PIB for remediation
            raPSENotTrusted_SendPIB = 0x03,            // Server does not trust PSE but will send PIB for remediation
            raPSENotPresent = 0x04
        }

        public enum enPSEManifestStatusCodes : uint
        {
            raPSEManifestOK = 0x00,                       // OK
            raPSEManifestDescTypeNotSupported = 0x01,     // DESC_TYPE_NOT_SUPPORTED 
            raPSEManifestISVSVNOutOfDate = 0x02,          // PSE_ISVSVN_OUT_OF_DATE
            raPSEManifestMiscSelectInvalid = 0x04,        // PSE_MISCSELECT_INVALID
            raPSEManifestAttributesInvalid = 0x08,        // PSE_ATTRIBUTES_INVALID
            raPSEManifestMRSIGNERInvalid = 0x10,          // PSE_MRSIGNER_INVALID
            raPSEManifestHWGIDRevoked = 0x20,             // PS_HW_GID_REVOKED
            raPSEManifestPrivRLVerMismatch = 0x40,        // PS_HW_PrivKey_Rlver_MISMATCH
            raPSEManifestSigRLVerMismatch = 0x80,         // PS_HW_SIG_Rlver_MISMATCH
            raPSEManifestHWCAIDInvalid = 0x100,           // PS_HW_CA_ID_INVALID
            raPSEManifestHWSecInfoInvalid = 0x200,        // PS_HW_SEC_INFO_INVALID
            raPSEManifestHWPSDASVNOutOfDate = 0x400       // PS_HW_PSDA_SVN_OUT_OF_DATE
        }
        #region Vars
        private static M4ResponseMessage msg4 = new M4ResponseMessage();                    // class variable for Message 4
        private static RNGCryptoServiceProvider rngCSP = new RNGCryptoServiceProvider();    // Microsoft Random Number Generator Cryptographic Service Provider for generating random numbers

        private byte[] ascBa;
        private string sharedKeyStr;
        private byte[] sharedKey;
        private static HttpResponseMessage iasQuoteResponse = null;
        #endregion

        private BuildMessage bMessage = new BuildMessage();
        private SpCmacAes cmacAES = new SpCmacAes();


        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);

        /// <summary>
        /// Build Message 4
        /// </summary>
        /// <param name="sigmaSequenceCheck">Service Provider Sequence (State) Check</param>
        /// <param name="m3Received">Message 3 from the client</param>
        /// <returns>Message 4 response to client</returns>
        public async Task<M4ResponseMessage> BuildMessage4(SpSequenceCheck sigmaSequenceCheck, M3RequestMessage m3Received)
        {
            log.Debug("BuildMessage4(.) started.");

            if (m3Received == null || sigmaSequenceCheck == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.PreconditionFailed);
                options.LogThrownException(e);
                throw e;
            }


            // Update Client state
            if (!sigmaSequenceCheck.UpdateState(Constants.SequenceState.Msg4))
            {
                Exception e = new HttpResponseException(System.Net.HttpStatusCode.PreconditionFailed);
                options.LogThrownException(e);
                throw e;
            }

            // Initialize Shared Key
            InitSharedKey(sigmaSequenceCheck);

            byte[] internalError = BitConverter.GetBytes((UInt32)enStatusCodes.raErrIasInternal);

            // Use debug/non-IAS creation path of Message 4, or use IAS
            if (SpStartup.iasConnectionMgr.UseIAS)
            {
                int retryCount = Constants.retryCount;

                while (retryCount-- > 0)
                {
                    // If configured to use a connection to the IAS server, setup the client and POST request message for a quote report.
                    await BuildIASMessage4(m3Received, sigmaSequenceCheck);

                    // retry if we have an internal IAS error
                    if (msg4.respHeader.respStatus.SequenceEqual(internalError))
                        log.Debug("IAS error. Retrying...");
                    else
                        break;  // No IAS internal error
                }

                if (msg4.respHeader.respStatus.SequenceEqual(internalError))
                    throw new HttpResponseException(System.Net.HttpStatusCode.ServiceUnavailable);
            }
            else
            {
                // Non-IAS/Simulation Connection
                // The following debug path should only be used for a temporary check of SGX Sigma communications
                // by setting the "UseIAS" default settings value to "false".
                BuildNonIasMessage4(sigmaSequenceCheck);
            }

            log.Debug("BuildMessage4(.) returning.");
            return msg4;
        }

        /// <summary>
        /// Creates a response to the message 3 Quote
        /// </summary>
        /// <param name="m3Received">Received Message 3 from client</param>
        /// <param name="sigmaSequenceCheck">Service Provide Sequence Check</param>
        /// <returns>Boolean of whether creation was successful or not</returns>
        private async Task<Boolean> BuildIASMessage4(M3RequestMessage m3Received, SpSequenceCheck sigmaSequenceCheck)
        {
            log.Debug("BuildIASMessage4(.) started.");
            Boolean success = false;

            if (msg4 == null || m3Received == null || sigmaSequenceCheck == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            try
            {
                // Check for presence of Platform Services Enclave (PSE) manifest
                bool IASPSEManifest = PSEManifestExists(m3Received);

                // Serialize the quote object to JSON and populate a StringContent object for the client request
                // Get the HTTP response
                await GetIASQuoteResponse(IASPSEManifest, m3Received, sigmaSequenceCheck);
                if (iasQuoteResponse == null)
                {
                    HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                    options.LogThrownException(e);
                    throw e;
                }


                // initialize
                uint statusCodeValue = (uint)enAttestationStatusCodes.raAttestationErrUnknown;
                bMessage.buildM4Response(out msg4);
                msg4.respHeader.sessionNonce = sigmaSequenceCheck.currentNonce;

                Boolean IASError = false;
                String IASErrorReason = "Unknown Error";

                // Setup a container for the attestation status code
                QuoteStatus qs = new QuoteStatus();
                qs.isvEnclaveQuoteStatus = "";

                // Assume that enclave isn't trusted and PSE isn't present until proven otherwise below
                char enclaveTrustValue = (char)enEnclaveTrustStatusCodes.raTrustNone;
                uint pseStatus = (uint)enPSETrustStatusCodes.raPSENotPresent;
                bool sendPIB = false;
                // No payload is sent unless client enclave is trusted

                switch (iasQuoteResponse.StatusCode)
                {
                    case HttpStatusCode.Created:
                        {
                            log.DebugFormat("Quote Response Headers JSON: {0}", iasQuoteResponse.Headers);

                            var quoteSignatureString = await iasQuoteResponse.Content.ReadAsStringAsync();
                            log.DebugFormat("Quote Response JSON: {0}", quoteSignatureString);

                            qs = await iasQuoteResponse.Content.ReadAsAsync<QuoteStatus>();
                            if (qs == null)
                            {
                                log.Debug("Error receiving Quote Status from IAS: Null");
                                Exception e = new HttpResponseException(System.Net.HttpStatusCode.NoContent);
                                options.LogThrownException(e);
                                throw e;
                            }

                            log.DebugFormat("Attestation Evidence Status: {0}", qs.isvEnclaveQuoteStatus);

                            bool validIAS = CheckValidQuoteSignature(quoteSignatureString);

                            // Test for valid IAS connection
                            byte[] nonceData = Convert.FromBase64String(qs.nonce);
                            if (!sigmaSequenceCheck.currentNonce.SequenceEqual(nonceData))
                            {
                                validIAS = false;
                                log.Debug("Nonce is invalid - IAS is not authentic. Exiting...");
                                msg4.respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrUnknown);
                            }
                            else
                                log.Debug("Nonce is valid - IAS is authentic.");

                            //Check the manifest status if it was sent
                            if (IASPSEManifest)
                            {
                                // NOTE: PSE Manifest Status should only be present when Quote Status is OK or EPID GROUP_OUT_OF_DATE
                                if (String.Equals(qs.isvEnclaveQuoteStatus, "GROUP_OUT_OF_DATE", StringComparison.Ordinal) ||
                                    String.Equals(qs.isvEnclaveQuoteStatus, "OK", StringComparison.Ordinal))
                                {
                                    if (qs.pseManifestStatus == null || String.IsNullOrEmpty(qs.pseManifestStatus.ToString()))
                                    {
                                        log.Debug("Error receiving PSE Manifest Status from IAS: Null");
                                        Exception e = new HttpResponseException(System.Net.HttpStatusCode.NoContent);
                                        options.LogThrownException(e);
                                        throw e;
                                    }

                                    if (qs.pseManifestStatus.Contains("OK"))
                                    {
                                        log.Debug("PseManifestStatus: OK");
                                    }
                                    else //PSE Manifest error codes
                                    {
                                        // Get status from PSE Manifest
                                        pseStatus = GetPSEManifestStatus(qs, sigmaSequenceCheck);
                                        if (pseStatus == (uint)enPSETrustStatusCodes.raPSENotTrusted_SendPIB ||
                                            pseStatus == (uint)enPSETrustStatusCodes.raPSETrusted_SendPIB)
                                        {
                                            // Send PIB to notify of PSE issue
                                            sendPIB = true;
                                        }

                                        log.Debug("*****PSE Manifest Status: " + pseStatus);
                                    }
                                }
                            }

                            // Handle EPID Pseudonym
                            ProcessEPIDPseudonym(qs);

                            // IAS status
                            if (validIAS && (String.Equals(qs.isvEnclaveQuoteStatus, "OK", StringComparison.Ordinal)))
                            {
                                msg4.respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrIasCreated);
                                statusCodeValue = (uint)enAttestationStatusCodes.raAttestationErrOK;

                                // This function assumes that client enclave already passes tests to be considered trusted
                                enclaveTrustValue = GetClientEnclaveTrustStatus(pseStatus);
                                if (enclaveTrustValue != (char)enEnclaveTrustStatusCodes.raTrustNone)
                                {
                                    BuildM4Payload(sharedKey, sigmaSequenceCheck);
                                    log.Debug("******* Send payload due to client enclave trust");
                                }
                            }
                            else // All IAS error scenarios start here
                            {
                                do
                                {
                                    msg4.respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrIasCreated);
                                    // Error scenarios
                                    if (!validIAS)
                                    {
                                        statusCodeValue = (uint)enAttestationStatusCodes.raAttestationErrUnknown;
                                        log.Debug("******* IAS is invalid!!! Bad signature or nonce");

                                        // May attempt retry here, or return error to client
                                    }
                                    else if (String.Equals(qs.isvEnclaveQuoteStatus, "SIGNATURE_INVALID", StringComparison.Ordinal))
                                    {
                                        statusCodeValue = (uint)enAttestationStatusCodes.raAttestationErrSigInvalid;
                                        log.Debug("******* IAS Signature Invalid Error -- Client needs to use correct signature");

                                        // May reject client
                                    }
                                    else if (String.Equals(qs.isvEnclaveQuoteStatus, "GROUP_REVOKED", StringComparison.Ordinal))
                                    {
                                        // get Revocation Reason
                                        // From RFC 5280 and https://en.wikipedia.org/wiki/Revocation_list 
                                        log.DebugFormat("Revocation reason: {0}", qs.revocationReason);

                                        // Handle revocation as needed
                                        statusCodeValue = (uint)enAttestationStatusCodes.raAttestationErrGrpRevoked;
                                        sendPIB = true;
                                        log.Debug("******* IAS Quote Group Revoked Error");

                                        // Invalid Enclave - Reject
                                    }
                                    else if (String.Equals(qs.isvEnclaveQuoteStatus, "SIGNATURE_REVOKED", StringComparison.Ordinal))
                                    {
                                        statusCodeValue = (uint)enAttestationStatusCodes.raAttestationErrSigRevoked;
                                        log.Debug("******* IAS Signature Revoked Error");

                                        // Invalid Enclave - Reject
                                    }
                                    else if (String.Equals(qs.isvEnclaveQuoteStatus, "KEY_REVOKED", StringComparison.Ordinal))
                                    {
                                        statusCodeValue = (uint)enAttestationStatusCodes.raAttestationErrKeyRevoked;
                                        log.Debug("******* IAS Key Revoked Error");

                                        // Invalid Enclave - Reject
                                    }
                                    else if (String.Equals(qs.isvEnclaveQuoteStatus, "SIGRL_VERSION_MISMATCH", StringComparison.Ordinal))
                                    {
                                        statusCodeValue = (uint)enAttestationStatusCodes.raAttestationErrSigRlVerMismatch;
                                        log.Debug("******* IAS SigRL Version Mismatch Error");

                                        // Have the client retry
                                        enclaveTrustValue = (char)enEnclaveTrustStatusCodes.raTrustRetry;

                                    }
                                    else if (String.Equals(qs.isvEnclaveQuoteStatus, "GROUP_OUT_OF_DATE", StringComparison.Ordinal))
                                    {
                                        statusCodeValue = (uint)enAttestationStatusCodes.raAttestationErrGrpOutOfDate;
                                        // Send PIB to notify of Group Out of Date error
                                        sendPIB = true;
                                        if (sigmaSequenceCheck.enclaveType.TrustEnclaveGroupOutOfDate)
                                        {
                                            // This call assumes that client enclave passes tests to be considered trusted
                                            enclaveTrustValue = GetClientEnclaveTrustStatus(pseStatus);
                                            if (enclaveTrustValue != (char)enEnclaveTrustStatusCodes.raTrustNone)
                                            {
                                                BuildM4Payload(sharedKey, sigmaSequenceCheck);
                                                log.Debug("******* IAS Group Out Of Date but trusted due to policy -- Send payload");
                                            }
                                            break; // exit the rest of error actions
                                        }
                                        else
                                        {
                                            log.Debug("******* IAS Group Out of Date Error -- not trusted due to policy");
                                            // Do Client Update
                                        }
                                    }
                                    else
                                    {
                                        statusCodeValue = (uint)enAttestationStatusCodes.raAttestationErrUnknown;
                                        log.Debug("******* IAS unexpected state error - isvEnclaveQuoteStatus unexpected response");

                                    } // Error Enclave Quote status cases

                                } while (false);
                            }

                            break;
                        }

                    // Getting here means that there was a problem with the quote; so send back an error status
                    case HttpStatusCode.BadRequest:
                        {
                            IASError = true;
                            msg4.respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrIasBadRequest);
                            IASErrorReason = "Bad Request Error";
                            log.Debug("******** Possible mismatch between the SPID used and the EPID signature policy. Check LinkableQuotes setting");
                            break;
                        }
                    case HttpStatusCode.Unauthorized:
                        {
                            IASError = true;
                            msg4.respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrIasUnauth);
                            IASErrorReason = "Unauthorized Error";
                            break;
                        }
                    case HttpStatusCode.InternalServerError:
                        {
                            IASError = true;
                            msg4.respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrIasInternal);
                            IASErrorReason = "Internal Server Error";
                            break;
                        }
                    default:
                        {
                            IASError = true;
                            msg4.respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrIasUnknown);
                            IASErrorReason = "Unknown Error";
                            break;
                        }

                }

                // On IAS error response
                if (IASError)
                {
                    // Zero fill the payload
                    // Update the payload size
                    statusCodeValue = (uint)enAttestationStatusCodes.raAttestationErrUnknown;
                    log.Debug("******* IAS " + IASErrorReason);
                }

                // Prepare Msg4 error specific sections
                if (sendPIB)
                {
                    if (qs.platformInfoBlob != null)
                    {
                        // Strip the TLV header from the PIB supplied by the IAS server and populate the msg4 PIB field.
                        msg4.respMsg4Body.platformInfo = bMessage.BlobStrToBa(qs.platformInfoBlob.Substring(qs.tlvLength));
                        enclaveTrustValue |= (char)enEnclaveTrustStatusCodes.raTrustCheckPIB;
                    }
                    else
                    {
                        log.Debug("*** PIB was not received from IAS although it was expected");
                        Exception e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                        options.LogThrownException(e);
                        throw e;
                    }
                }
                else
                {
                    if (qs.platformInfoBlob != null)
                    {
                        log.Debug("*** PIB was received from IAS although it was not expected");
                        Exception e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                        options.LogThrownException(e);
                        throw e;
                    }
                }

                // Finish processing all cases
                // isvCryptPayloadSize||CryptIv||isvPayloadTag||isvPayload

                // Set flag for status
                if (statusCodeValue == (uint)enAttestationStatusCodes.raAttestationErrOK)
                    success = true;

                log.Debug("*****IAS Status Code: " + statusCodeValue);
                FinishM4Response(enclaveTrustValue, sigmaSequenceCheck);

                // This is the successful end of the sequence. 
                // Reset the state machine and return M4
                string msg4JsonString = JsonConvert.SerializeObject(msg4,
                                            Newtonsoft.Json.Formatting.None,
                                            new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });
                log.Info("*********** Remote Attestation Sequence Successful with IAS connection");
                log.Info("*********** Sending Msg4");
                log.DebugFormat("*********** Msg4 JSON string: {0}", msg4JsonString);
                log.DebugFormat("*********** Msg4 Base16 Encoded String: {0}", msg4.GetMsgString());
            }
            catch (HttpResponseException)
            {
                // This catch block is to prevent subsequent catch blocks from catching HttpResponseExceptions.
                // Because we are using Visual Studio 2012, we are limited to an older version of the C#
                // language that does not support exception filters. When C# 6 is available to us, it may
                // be decided that exception filters are a better solution than this catch block.
                throw;
            }
            catch (Exception quotePostError)
            {
                options.LogCaughtErrorException(quotePostError);

                msg4 = null;

                // Handle the case where there is no HTTP response from IAS
                log.Debug("****** IAS POST Failure - aborting message sequence");
                log.DebugFormat("**** IAS Error **** {0}", quotePostError);
                log.Debug(" Exception: " + quotePostError.InnerException.Message);

                // Reset the state machine 
                log.Debug("******* IAS HTTP/Connection Error");
                log.Debug("**** Error. Message 4 Response Status: " + (uint)enAttestationStatusCodes.raAttestationErrUnknown);
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }
            finally
            {
                // Dispose of the IAS response message and clean up the shared client for the next provisioning sequence.
                if (iasQuoteResponse != null)
                    iasQuoteResponse.Dispose();
            }

            log.DebugFormat("BuildIASMessage4(.) returning {0}.", success);
            return success;
        }

        /// <summary>
        /// Build Message 4 response for Non-IAS Connection; Used for Debug only
        /// </summary>
        /// <returns>Message 4 response to client</returns>
        private void BuildNonIasMessage4(SpSequenceCheck sigmaSequenceCheck)
        {
            log.Debug("BuildNonIasMessage4(.) started.");

            if (sigmaSequenceCheck == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            try
            {
                bMessage.buildM4Response(out msg4);
                msg4.respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrNone);
                msg4.respMsg4Body.platformInfo = null;
                msg4.respHeader.sessionNonce = sigmaSequenceCheck.currentNonce;
                char enclaveTrustValue = (char)enEnclaveTrustStatusCodes.raTrustAll;

                BuildM4Payload(sharedKey, sigmaSequenceCheck);
                FinishM4Response(enclaveTrustValue, sigmaSequenceCheck);

                // This is the successful end of the sequence. 
                // Reset the state machine and return M4
                log.Info("*********** Remote Attestation Sequence Successful with Simulated IAS");
                log.Info("*********** Sending Msg4");
                log.Debug("Message 4 Response Status: " + (uint)enAttestationStatusCodes.raAttestationErrOK);

                log.DebugFormat("*********** Msg4 JSON string: {0}", JsonConvert.SerializeObject(msg4));
                log.DebugFormat("*********** Msg4 Base16 Encoded String: {0}", msg4.GetMsgString());
            }
            catch (Exception e)
            {
                options.LogCaughtErrorException(e);
                log.Debug("Non-IAS Message 4 Creation: Failed to create message 4 response. " + e.Message);
                HttpResponseException eNew = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(eNew);
                throw eNew;
            }

            log.Debug("BuildNonIasMessage4(.) returning.");
        }

        /// <summary>
        /// Build the Message 4 Payload
        /// </summary>
        /// <param name="SharedKey">Shared Key for ECC</param>
        public void BuildM4Payload(byte[] eccSharedKey, SpSequenceCheck sigmaSequenceCheck)
        {
            log.Debug("BuildM4Payload(.) started.");

            if (eccSharedKey == null || sigmaSequenceCheck == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            if (msg4 == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // This Message 4 building implementation is insecure and more robust security measures should be applied for Production use,
            // particularly the encryption of the payload

            // M4 = m4 = msg4 = IAS_PlatformInfo||PlatformInfoReserved||attestationStatus||cmacStatus||
            // Build the payload
            // NOTE: At this point, the Service Provider must apply some level of protection in 
            // the form of encryption for at least the Key portion of the payload.
            // Reasonable schemes might include AES GCM or AES then HMAC to provide both encryption and 
            // integrity in one step.
            // Because AES GCM is already supported by the SGX SDK, this demonstration will use AES GCM.
           
                SetEncryptAndClearMessages(eccSharedKey, sigmaSequenceCheck);
            log.Debug("BuildM4Payload(.) returning.");
        }

        /// <summary>
        /// Copy final calculated values for Message 4
        /// </summary>
        /// <param name="statusCodeValue">IAS Response status code</param>
        /// <param name="currentDerivedKey">Shared Key value</param>
        public void FinishM4Response(char enclaveTrustValue, SpSequenceCheck sigmaSequenceCheck)
        {
            log.Debug("FinishM4Response(.) started.");

            if (sigmaSequenceCheck == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            if (msg4 == null || ascBa == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // Add enclave attestation status to msg4
            byte[] enclaveTrustValBa = BitConverter.GetBytes(enclaveTrustValue);
            System.Buffer.BlockCopy(enclaveTrustValBa, 0, ascBa, 0, enclaveTrustValBa.Length);

            // Add duration if attestation and payload are valid
            byte[] durationBa;
            uint duration;
            if (sigmaSequenceCheck.enclaveType.LeaseDuration < 0 ||
                sigmaSequenceCheck.enclaveType.LeaseDuration > Constants.M4MaxDuration)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.PreconditionFailed);
                options.LogThrownException(e);
                throw e;
            }
            else if (msg4.respMsg4Body.isvPayload != null)
            {
                duration = (uint)sigmaSequenceCheck.enclaveType.LeaseDuration;
                durationBa = BitConverter.GetBytes(duration);
                System.Buffer.BlockCopy(durationBa, 0, ascBa, Constants.M4DurationLoc, Constants.M4DurationLen);
            }

            // ascBa now holds:
            // Byte 0: Enclave attestation status (four possible values)
            // Bytes 1 - 3: Lease duration
            msg4.respMsg4Body.attestationStatus = ascBa;
            string attestStatStr = bMessage.BaToBlobStr(msg4.respMsg4Body.attestationStatus);

            // Derive the "MK" key using MK = AES-CMAC(KDK, 0x01||’MK’||0x00||0x80 ||0x00)
            byte[] MK = bMessage.KeyLabelToKey(Constants.MK, sigmaSequenceCheck.currentKDK);

            // Compute the cmac of the attestation status and populate the cmacStatus field.
            msg4.respMsg4Body.cmacStatus = cmacAES.Value(MK, msg4.respMsg4Body.attestationStatus);

            string m4MessageString = msg4.GetMsgString();
            msg4.respHeader.msgLength = BitConverter.GetBytes((UInt32)m4MessageString.Length / 2);  //Byte length = base16 string length/2 

            log.Debug("FinishM4Response(.) returning.");
        }

        /// <summary>
        /// Initialize Shared Key value based on the Sigma State
        /// </summary>
        /// <param name="sigmaSequenceCheck">Service Provider Sequence (State) Check</param>
        private void InitSharedKey(SpSequenceCheck sigmaSequenceCheck)
        {
            log.Debug("InitSharedKey(.) started.");

            if (sigmaSequenceCheck == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // Derive the "SharedKey" key using SharedKey = AES-CMAC(KDK, 0x01||’SK’||0x00||0x80 ||0x00)
            sharedKey = bMessage.KeyLabelToKey(Constants.SK, sigmaSequenceCheck.currentKDK);
            sharedKeyStr = bMessage.BaToBlobStr(sharedKey);
            ascBa = new byte[Constants.RAStatusCodeLen];

            log.Debug("InitSharedKey(.) returning.");
        }

        // This only gets called if Client Enclave appears trustworthy
        private char GetClientEnclaveTrustStatus(uint PSETrusted)
        {
            log.Debug("GetClientEnclaveTrustStatus(.) started.");
            char ClientTrustCode;

            if (PSETrusted == (uint)enPSETrustStatusCodes.raPSENotPresent ||
                    PSETrusted == (char)enPSETrustStatusCodes.raPSETrusted ||
                    PSETrusted == (char)enPSETrustStatusCodes.raPSETrusted_SendPIB)
            {
                ClientTrustCode = (char)enEnclaveTrustStatusCodes.raTrustAll;
            }
            else if (PSETrusted == (uint)enPSETrustStatusCodes.raPSENotTrusted ||
                    PSETrusted == (char)enPSETrustStatusCodes.raPSENotTrusted_SendPIB)
            {
                ClientTrustCode = (char)enEnclaveTrustStatusCodes.raTrustEnclaveOnly;
            }
            else
            {
                ClientTrustCode = (char)enEnclaveTrustStatusCodes.raTrustNone;
            }
            log.Debug("GetClientEnclaveTrustStatus(.) returning.");
            return ClientTrustCode;

        }
        /// <summary>
        /// Gets the error code from the PSE Manifest
        /// </summary>
        /// <param name="qs">Status in the Quote</param>
        /// <returns>Byte array code of the quote status</returns>
        private uint GetPSEManifestStatus(QuoteStatus qs, SpSequenceCheck sigmaSequenceCheck)
        {
            log.Debug("GetPSEManifestStatus(.) started.");

            if (qs == null || sigmaSequenceCheck == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            uint pseMask = 0;
            if (qs.pseManifestStatus.Contains("DESC_TYPE_NOT_SUPPORTED"))
                pseMask |= (uint)enPSEManifestStatusCodes.raPSEManifestDescTypeNotSupported;
            if (qs.pseManifestStatus.Contains("PSE_ISVSVN_OUT_OF_DATE"))
                pseMask |= (uint)enPSEManifestStatusCodes.raPSEManifestISVSVNOutOfDate;
            if (qs.pseManifestStatus.Contains("PSE_MISCSELECT_INVALID"))
                pseMask |= (uint)enPSEManifestStatusCodes.raPSEManifestMiscSelectInvalid;
            if (qs.pseManifestStatus.Contains("PSE_ATTRIBUTES_INVALID"))
                pseMask |= (uint)enPSEManifestStatusCodes.raPSEManifestAttributesInvalid;
            if (qs.pseManifestStatus.Contains("PSE_MRSIGNER_INVALID"))
                pseMask |= (uint)enPSEManifestStatusCodes.raPSEManifestMRSIGNERInvalid;
            if (qs.pseManifestStatus.Contains("PS_HW_GID_REVOKED"))
                pseMask |= (uint)enPSEManifestStatusCodes.raPSEManifestHWGIDRevoked;
            if (qs.pseManifestStatus.Contains("PS_HW_PrivKey_Rlver_MISMATCH"))
                pseMask |= (uint)enPSEManifestStatusCodes.raPSEManifestPrivRLVerMismatch;
            if (qs.pseManifestStatus.Contains("PS_HW_SIG_Rlver_MISMATCH"))
                pseMask |= (uint)enPSEManifestStatusCodes.raPSEManifestSigRLVerMismatch;
            if (qs.pseManifestStatus.Contains("PS_HW_CA_ID_INVALID"))
                pseMask |= (uint)enPSEManifestStatusCodes.raPSEManifestHWCAIDInvalid;
            if (qs.pseManifestStatus.Contains("PS_HW_SEC_INFO_INVALID"))
                pseMask |= (uint)enPSEManifestStatusCodes.raPSEManifestHWSecInfoInvalid;
            if (qs.pseManifestStatus.Contains("PS_HW_PSDA_SVN_OUT_OF_DATE"))
                pseMask |= (uint)enPSEManifestStatusCodes.raPSEManifestHWPSDASVNOutOfDate;

            // Generate message for client based on PSE Manifest
            uint pseStatus = CheckPSEResult(pseMask, sigmaSequenceCheck);

            log.Debug("GetPSEManifestStatus(.) returning.");
            return pseStatus;
        }

        /// <summary>
        /// Checks the PSE Mask and determines the result status
        /// </summary>
        /// <param name="pseMask">PSE Mask status</param>
        private uint CheckPSEResult(uint pseMask, SpSequenceCheck sigmaSequenceCheck)
        {
            log.Debug("CheckPSEResult(.) started.");

            if (sigmaSequenceCheck == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            var resPSEOutOfDate = pseMask & (uint)(enPSEManifestStatusCodes.raPSEManifestISVSVNOutOfDate |
                enPSEManifestStatusCodes.raPSEManifestHWPSDASVNOutOfDate);

            var resPSENoTrust = pseMask & (uint)(enPSEManifestStatusCodes.raPSEManifestDescTypeNotSupported |
                enPSEManifestStatusCodes.raPSEManifestMiscSelectInvalid |
                enPSEManifestStatusCodes.raPSEManifestAttributesInvalid |
                enPSEManifestStatusCodes.raPSEManifestMRSIGNERInvalid |
                enPSEManifestStatusCodes.raPSEManifestHWCAIDInvalid |
                enPSEManifestStatusCodes.raPSEManifestHWSecInfoInvalid);

            var resPSENoTrust_SendPIB = pseMask & (uint)(enPSEManifestStatusCodes.raPSEManifestPrivRLVerMismatch |
                enPSEManifestStatusCodes.raPSEManifestSigRLVerMismatch |
                enPSEManifestStatusCodes.raPSEManifestHWGIDRevoked);



            // Generate PSE status output based on results.
            // (Also store this information in server database if it exists)
            uint pseStatus = (uint)enPSETrustStatusCodes.raPSETrusted;

            // Do this test first in case there are other errors which supercede it
            if (resPSEOutOfDate != 0)
            {
                log.Debug("The Platform Services TCB is out of date but not revoked. Service Provider may establish full or reduced trust");
                if (sigmaSequenceCheck.enclaveType.TrustPSEOutOfDate)
                {
                    // Full trust
                    pseStatus = (uint)enPSETrustStatusCodes.raPSETrusted_SendPIB;
                }
                else
                {
                    // Reduced trust
                    // Pass PIB to the platform for analysis.  May result in upgrade request.
                    pseStatus = (uint)enPSETrustStatusCodes.raPSENotTrusted_SendPIB;
                }

            }
            if (resPSENoTrust != 0)
            {
                log.Debug("Platform Services has invalid parameters - Service Provider does not trust the Platform Services Enclave");
                pseStatus |= (uint)enPSETrustStatusCodes.raPSENotTrusted;
            }
            if (resPSENoTrust_SendPIB != 0)
            {
                log.Debug("Platform Services Enclave version mismatch or HWGID revoked - PSE not trusted - send PIB for remediation");
                //Pass PIB if present to platform for analysis. Client needs to try again
                pseStatus = (uint)enPSETrustStatusCodes.raPSENotTrusted_SendPIB;
            }

            log.DebugFormat("CheckPSEResult(.) returning {0}.", pseStatus);
            return pseStatus;
        }

        /// <summary>
        /// Process the EPID Pseudonym
        /// </summary>
        /// <param name="qs">Status of the Quote</param>
        private void ProcessEPIDPseudonym(QuoteStatus qs)
        {
            log.Debug("ProcessEPIDPseudonym(.) started.");

            if (qs == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // Store the EPID pseudonym if we are using a linkable quote
            if (SpStartup.iasConnectionMgr.LinkableQuotes)
            {
                byte[] epidPseudo = Convert.FromBase64String(qs.epidPseudonym);
                string epStr = bMessage.BaToBlobStr(epidPseudo);
                log.DebugFormat("EPID B: {0}", epStr.Substring(0, Constants.EPIDpseudonymLen));
                log.DebugFormat("EPID K: {0}", epStr.Substring(Constants.EPIDpseudonymLen, Constants.EPIDpseudonymLen));

                //
                // Save the pseudonym to compare with other pseudonyms later. Match=same client as before.
                //
            }

            log.Debug("ProcessEPIDPseudonym(.) returning.");
        }

        /// <summary>
        /// Initialize Crypt Initialization Vector
        /// </summary>
        /// <returns>Byte array of the Crypt Initialization Vector</returns>
        private byte[] InitializeCryptIV()
        {
            log.Debug("InitializeCryptIV(.) started.");

            // Initialization Vector should be created per the suggested practices recommended by NIST
            // http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf

            // More secure generation of Initialization Vector (IV) should be implemented as RNG is predictable. Follow NIST standard on creation guidelines. 
            byte[] cryptIV = new byte[Constants.IVLen];

            log.Debug("Generating CryptIV");
            int count = 0;
            do
            {
                rngCSP.GetBytes(cryptIV);
            } while (count++ < Constants.IVLen);

            rngCSP.Dispose();

            log.Debug("InitializeCryptIV(.) returning.");
            return cryptIV;
        }

        /// <summary>
        /// Initialize Random Payload
        /// </summary>
        /// <returns>Byte array of the Crypt Initialization Vector</returns>
        private byte[] InitializeRandomPayload()
        {
            log.Debug("InitializeRandomPayload(.) started.");

            // Initialization Vector should be created per the suggested practices recommended by NIST
            // http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf

            // More secure generation of Initialization Vector (IV) should be implemented as RNG is predictable. Follow NIST standard on creation guidelines. 
            byte[] payload = new byte[Constants.RandomPayload];

            log.Debug("Generating Random Payload");
            int count = 0;
            do
            {
                rngCSP.GetBytes(payload);
            } while (count++ < Constants.RandomPayload);

            rngCSP.Dispose();

            log.Debug("InitializeRandomPayload(.) returning.");
            return payload;
        }

        /// <summary>
        /// Check whether the PSE Manifest exists in Message 3
        /// </summary>
        /// <param name="m3Received">Message 3</param>
        /// <returns>Boolean whether the PSE Manifest exists or not</returns>
        private Boolean PSEManifestExists(M3RequestMessage m3Received)
        {
            log.Debug("PSEManifestExists(.) started.");

            if (m3Received == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            log.Debug("Checking PSE Manifest exists");

            // No response received
            if (m3Received.reqM3Body.secProperty == null)
            {
                log.Debug("PSEManifestExists(.) returning false because secProperty==null.");
                return false;
            }

            if (m3Received.reqM3Body.secProperty.SequenceEqual(MsgInitValues.DS_ZERO_BA256))
            {
                log.Debug("PSE Manifest does not exist");
                log.Debug("PSEManifestExists(.) returning false.");
                return false;
            }

            log.Debug("PSE Manifest exists");
            log.Debug("PSEManifestExists(.) returning true.");
            return true;
        }

        private void SetEncryptAndClearMessages(byte[] eccSharedKey, SpSequenceCheck sigmaSequenceCheck)
        {
            log.Debug("SetEncryptMessage(.) started.");

            if (eccSharedKey == null || sigmaSequenceCheck == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // (Intel Performance Primitives) IPP Wrapper
            ippApiWrapper ippWrapper = new ippApiWrapper();

            if (msg4 == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            try
            {
                byte[] cryptIV = InitializeCryptIV();
                byte[] Tag = new byte[Constants.AESGCMTagLen];

         
                // Deliver the ISV Key and Certificate for Remote Attestation
                // Currently using the ISV Key and Certificate for payload
                // This data may be replaced with desired data to be provisioned to the device
                byte[] encMessage = Constants.isvKey;
                byte[] clearMessage = Constants.isvCert;
                
                //// isvCryptPayloadSize denotes the size of encrypted key only, not including certificate.
                msg4.respMsg4Body.isvCryptPayloadSize = BitConverter.GetBytes(Constants.isvKey.Length); // Size of the encrypted part of the payload
                msg4.respMsg4Body.isvClearPayloadSize = BitConverter.GetBytes(Constants.isvCert.Length);

                // Encrypt the message using Intel Performance Primitives (IPP)
                // ISV-specific cryptographic functions may be used in place here
                // Client application would need to ensure compatibility for usage
                if (ippWrapper.EncryptData(encMessage, eccSharedKey, cryptIV, clearMessage, encMessage.Length, ref encMessage, ref Tag) == false)
                {
                    HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                    options.LogThrownException(e);
                    throw e;
                }

                log.DebugFormat("encMessage: {0}", bMessage.BaToBlobStr(encMessage));
                byte[] payloadBuffer = new byte[encMessage.Length + clearMessage.Length];
                System.Buffer.BlockCopy(encMessage, 0, payloadBuffer, 0, encMessage.Length);
                System.Buffer.BlockCopy(clearMessage, 0, payloadBuffer, encMessage.Length, clearMessage.Length);
                msg4.respMsg4Body.isvPayload = payloadBuffer;
                msg4.respMsg4Body.CryptIv = cryptIV;
                msg4.respMsg4Body.isvPayloadTag = Tag;
                
            }
            catch (HttpResponseException)
            {
                // This catch block is to prevent subsequent catch blocks from catching HttpResponseExceptions.
                // Because we are using Visual Studio 2012, we are limited to an older version of the C#
                // language that does not support exception filters. When C# 6 is available to us, it may
                // be decided that exception filters are a better solution than this catch block.
                throw;
            }
            catch (Exception e)
            {
                options.LogCaughtErrorException(e);
                Console.WriteLine(e.Message);
                HttpResponseException eNew = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(eNew);
                throw eNew;
            }

            log.Debug("SetEncryptMessage(.) returning.");
        }


        private void SetISVEncryptAndClearMessages(byte[] eccSharedKey, SpSequenceCheck sigmaSequenceCheck)
        {
            log.Debug("SetISVEncryptMessage(.) started.");

            if (eccSharedKey == null || sigmaSequenceCheck == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // (Intel Performance Primitives) IPP Wrapper
            ippApiWrapper ippWrapper = new ippApiWrapper();
            byte[] encMessage;
            byte[] clearMessage;
            int clearMessageLen = 0;

            if (msg4 == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            try
            {
                byte[] cryptIV = InitializeCryptIV();
                byte[] Tag = new byte[Constants.AESGCMTagLen];
                if (!String.IsNullOrEmpty(sigmaSequenceCheck.enclaveType.Payload.Encrypt))
                {
                    if (sigmaSequenceCheck.enclaveType.Payload.Encrypt.Equals("Random", StringComparison.OrdinalIgnoreCase))
                        encMessage = InitializeRandomPayload();
                    else
                        encMessage = File.ReadAllBytes(sigmaSequenceCheck.enclaveType.Payload.Encrypt);
                    log.DebugFormat("***Original content to encrypt: {0}", bMessage.BaToBlobStr(encMessage));
                    msg4.respMsg4Body.isvCryptPayloadSize = BitConverter.GetBytes(encMessage.Length);
                }
                else
                {
                    encMessage = null;
                    log.Debug("***No content to encrypt");
                }
                if (!String.IsNullOrEmpty(sigmaSequenceCheck.enclaveType.Payload.Clear))
                {
                    if (sigmaSequenceCheck.enclaveType.Payload.Clear.Equals("Random", StringComparison.OrdinalIgnoreCase))
                        clearMessage = InitializeRandomPayload();
                    else
                        clearMessage = File.ReadAllBytes(sigmaSequenceCheck.enclaveType.Payload.Clear);
                    clearMessageLen = clearMessage.Length;
                    log.DebugFormat("***Original content to send in the clear: {0}", bMessage.BaToBlobStr(clearMessage));
                    msg4.respMsg4Body.isvClearPayloadSize = BitConverter.GetBytes(clearMessageLen);
                }
                else
                {
                    clearMessage = null;
                    log.Debug("***No content to send in the clear");
                }

                // Encrypt the message using Intel Performance Primitives (IPP)
                // ISV-specific cryptographic functions may be used in place here
                // Client application would need to ensure compatibility for usage
                if (encMessage != null)
                {
                    log.DebugFormat("Shared Key: {0}", bMessage.BaToBlobStr(eccSharedKey));
                    if (ippWrapper.EncryptData(encMessage, eccSharedKey, cryptIV, clearMessage, encMessage.Length, ref encMessage, ref Tag) == false)
                    {
                        HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                        options.LogThrownException(e);
                        throw e;
                    }

                    log.DebugFormat("Encoded content: {0}", bMessage.BaToBlobStr(encMessage));
                    byte[] payloadBuffer = new byte[encMessage.Length + clearMessageLen];
                    System.Buffer.BlockCopy(encMessage, 0, payloadBuffer, 0, encMessage.Length);
                    if (clearMessage != null)
                        System.Buffer.BlockCopy(clearMessage, 0, payloadBuffer, encMessage.Length, clearMessageLen);
                    msg4.respMsg4Body.isvPayload = payloadBuffer;

                
                    msg4.respMsg4Body.CryptIv = cryptIV;
                    msg4.respMsg4Body.isvPayloadTag = Tag;
                    log.DebugFormat("CryptIV: {0}", bMessage.BaToBlobStr(cryptIV));
                    log.DebugFormat("Tag: {0}", bMessage.BaToBlobStr(Tag));
                }
                else if (clearMessage != null)
                {
                    msg4.respMsg4Body.isvPayload = clearMessage;
                }
            }
            catch (HttpResponseException)
            {
                // This catch block is to prevent subsequent catch blocks from catching HttpResponseExceptions.
                // Because we are using Visual Studio 2012, we are limited to an older version of the C#
                // language that does not support exception filters. When C# 6 is available to us, it may
                // be decided that exception filters are a better solution than this catch block.
                throw;
            }
            catch (Exception e)
            {
                options.LogCaughtErrorException(e);
                Console.WriteLine(e.Message);
                HttpResponseException eNew = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(eNew);
                throw eNew;
            }

            log.Debug("SetISVEncryptMessage(.) returning.");
        }

        /// <summary>
        /// Queries IAS for verification response from client enclave quote
        /// </summary>
        /// <param name="IASPSEManifest">Intel Attestation Service (IAS) Platform Services Enclave (PSE) Manifest</param>
        /// <param name="m3Received">Message 3 from client</param>
        /// <returns>Response from IAS about client quote</returns>
        private async Task<HttpResponseMessage> GetIASQuoteResponse(Boolean IASPSEManifest, M3RequestMessage m3Received, SpSequenceCheck sigmaSequenceCheck)
        {
            log.Debug("GetIASQuoteResponse(.) started.");

            // Build IAS URI
            // Pull the URI for the IAS server from the configuration file                
            string iasPostRequestString = SpStartup.iasConnectionMgr.iasUri + Constants.AttestationReportUri;  // NOTE: "attestation/sgx/v1/report" has no trailing slash.


            try
            {
                if (iasQuoteResponse == null)
                {
                    iasQuoteResponse = new HttpResponseMessage();
                    if (iasQuoteResponse == null)
                    {
                        HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                        options.LogThrownException(e);
                        throw e;
                    }
                }

                log.DebugFormat("Sending IAS POST Request using: {0}", iasPostRequestString);
                log.DebugFormat("******** IAS POST Response:  {0}", iasQuoteResponse.ReasonPhrase);

                System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
                if (IASPSEManifest)
                {
                    // Process for PSE Manifest
                    var m3Quote = new QuotePSE()
                    {
                        isvEnclaveQuote = m3Received.reqM3Body.quote,
                        pseManifest = m3Received.reqM3Body.secProperty,
                        nonce = sigmaSequenceCheck.currentNonce
                    };
                    if (iasQuoteResponse != null)
                    {
                        iasQuoteResponse.Dispose();
                    }
                    iasQuoteResponse = await sigmaSequenceCheck.iasClient.PostAsJsonAsync(iasPostRequestString, m3Quote);
                }
                else    // No PSE Manifest
                {
                    var m3Quote = new QuoteNoPSE()
                    {
                        isvEnclaveQuote = m3Received.reqM3Body.quote,
                        nonce = sigmaSequenceCheck.currentNonce
                    };

                    log.DebugFormat("******** Raw nonce for IAS:  {0}", BitConverter.ToString(m3Quote.nonce));
                    if (iasQuoteResponse != null)
                    {
                        iasQuoteResponse.Dispose();
                    }
                    iasQuoteResponse = await sigmaSequenceCheck.iasClient.PostAsJsonAsync(iasPostRequestString, m3Quote);
                }
            }
            catch (Exception e)
            {
                options.LogCaughtErrorException(e);
                log.Debug("Error getting IAS Quote Response: " + e.Message);
                if (iasQuoteResponse != null)
                {
                    iasQuoteResponse.Dispose();
                    iasQuoteResponse = null;
                }
                Exception newException = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(newException);
                throw newException;
            }

            return null;
        }

        /// <summary>
        /// Verify that the Quote Signature is valid and correct
        /// </summary>
        /// <param name="iasQuoteResponse">Response from IAS about the quote</param>
        /// <param name="quoteSignatureString">Quote Signature as a string</param>
        /// <returns>Boolean whether the Quote Signature is valid or not</returns>
        private bool CheckValidQuoteSignature(string quoteSignatureString)
        {
            log.Debug("CheckValidQuoteSignature(.) started.");

            if (iasQuoteResponse == null || quoteSignatureString == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // Verify IAS signature 
            IEnumerable<string> signature = iasQuoteResponse.Headers.GetValues(Constants.IASReportSig);
            if (signature == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.PreconditionFailed);
                options.LogThrownException(e);
                throw e;
            }

            byte[] quoteSignature = Convert.FromBase64String(signature.FirstOrDefault());
            string quoteSignatureStr = bMessage.BaToBlobStr(quoteSignature);
            log.DebugFormat("Quote signature: {0}", quoteSignatureStr);

            var encoder = new UTF8Encoding();
            byte[] bytesToVerify = encoder.GetBytes(quoteSignatureString);
            bool validIAS = false;

            using (SHA256Managed Sha = new SHA256Managed())
            {
                if (Sha == null)
                {
                    HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                    options.LogThrownException(e);
                    throw e;
                }

                try
                {
                    byte[] hash = Sha.ComputeHash(bytesToVerify);

                    // Verify data against signature
                    if (SpStartup.iasConnectionMgr.RSA.VerifyHash(hash, quoteSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                    {
                        log.Debug("Attestation server sent valid signature - IAS is authentic.");
                        validIAS = true;
                    }
                    else
                    {
                        validIAS = false;
                        log.Debug("Attestation server sent invalid signature - IAS is not authentic. Exiting...");
                        msg4.respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrVerificationSigCheckFail);
                    }
                }
                catch (Exception e)
                {
                    options.LogCaughtErrorException(e);
                    log.Debug("Failure checking quote signature. " + e.Message);
                    Exception newException = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                    options.LogThrownException(newException);
                    throw newException;
                }
            }

            log.DebugFormat("CheckValidQuoteSignature(.) returning {0}.", validIAS);
            return validIAS;
        }

    }
}
