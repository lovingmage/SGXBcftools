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
using System.IO;


namespace RaSpRef
{
    class Msg3
    {
        private BuildMessage bMessage = new BuildMessage();
        private SpCmacAes cmacAES = new SpCmacAes();


        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);
        private SpSequenceCheck sigmaSequenceCheck = null;

        /// <summary>
        /// Process Message 3 and Build Message 4
        /// </summary>
        /// <param name="Request">Message 3 Client Response</param>
        /// <param name="sigmaSequenceCheck">Service Provider Sequence (State) Check</param>
        /// <returns>Message 4 Repsonse to Client</returns>
        public async Task<M4ResponseMessage> ProcessMessage3(HttpRequestMessage Request, SpSequenceCheck sigmaSequenceChk)
        {
            log.Debug("ProcessMessage3(.) started.");

            if (Request == null || sigmaSequenceChk == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.PreconditionFailed);
                options.LogThrownException(e);
                throw e;
            }

            sigmaSequenceCheck = sigmaSequenceChk;

            // Update Client state
            if (!sigmaSequenceCheck.UpdateState(Constants.SequenceState.Msg3))
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.PreconditionFailed);
                options.LogThrownException(e);
                throw e;
            }

            var result = Request.Content.ReadAsStringAsync();
            string jsonMsg3Request = result.Result;
            M3RequestMessage m3Received = new M3RequestMessage();
            try
            {
                // Attempt to parse request in message 3 
                m3Received = JsonConvert.DeserializeObject<M3RequestMessage>(jsonMsg3Request);
            }
            catch (Exception msg3ReqError)
            {
                log.DebugFormat("******* Message 3 JSON Content Error: {0}", msg3ReqError);
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            if (m3Received == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.PreconditionFailed);
                options.LogThrownException(e);
                throw e;
            }

            // Check the nonce and the base16 encoded length of the inbound request
            string m3ReceivedString = m3Received.GetMsgString();
            log.Info("******* Received M3 Request");
            log.DebugFormat("{0}{1}", Request.Headers, jsonMsg3Request);
            log.DebugFormat("M3 Base16 Encoded String: {0}", m3ReceivedString);

            // If failed a check, throw an error
            // Getting to this point means there was a problem with the M3 content (including possible quote check failure).    
            // Reset the state machine and return "Forbidden"

            // Check whether to use Nonce or not, and is valid
            bool nonceCheck = sigmaSequenceCheck.currentNonce.SequenceEqual(m3Received.reqHeader.nonce);
            if (!nonceCheck)
            {
                log.Debug("Invalid Message 3 Nonce");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            // Check the message has the correct length
            bool lengthCheck = CheckMessageLength(m3Received, m3ReceivedString);
            if (!lengthCheck)
            {
                log.Debug("Invalid Message 3 Length");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            // Check the M3 components & Ga
            byte[] m3Ga = new byte[m3Received.reqM3Body.gaX.Length + m3Received.reqM3Body.gaY.Length];
            System.Buffer.BlockCopy(m3Received.reqM3Body.gaX, 0, m3Ga, 0, m3Received.reqM3Body.gaX.Length);
            System.Buffer.BlockCopy(m3Received.reqM3Body.gaY, 0, m3Ga, m3Received.reqM3Body.gaX.Length, m3Received.reqM3Body.gaY.Length);
            string m3GaStr = bMessage.BaToBlobStr(m3Ga);
            string currentGaStr = bMessage.BaToBlobStr(sigmaSequenceCheck.currentGa);

            // Check the ga is correct
            bool gaCheck = CheckGa(currentGaStr, m3GaStr);
            if (!gaCheck)
            {
                log.Debug("Invalid Message 3 ga");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            // Check that the CMAC is correct
            bool cmacCheck = CheckCmac(m3Received, m3GaStr);
            if (!cmacCheck)
            {
                log.Debug("Invalid Message 3 CMAC");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            string m3QuoteStr = bMessage.BaToBlobStr(m3Received.reqM3Body.quote);
            if (String.IsNullOrEmpty(m3QuoteStr))
            {
                log.Debug("Message 3 Quote is NULL");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            // Get MRSIGNER and ISVPRODID from the Quote to find the correct enclave type from Enclave.json
            string MRSIGNERString = m3QuoteStr.Substring((int)Constants.QuoteInfo.MRSIGNEROffset * 2, Constants.QuoteInfo.MRSIGNERSize * 2);     // MR Enclave String from Quote
            log.InfoFormat("Quote came from enclave with MRSIGNER:   {0}", MRSIGNERString);

            ushort ISVPRODID = (ushort)BitConverter.ToInt16(bMessage.BlobStrToBa(m3QuoteStr.Substring((int)Constants.QuoteInfo.ISVPRODIDOffset * 2, 4)), 0);
            log.DebugFormat("ISVPRODID:\t{0}", ISVPRODID);

            sigmaSequenceCheck.SetEnclaveType(MRSIGNERString, ISVPRODID);

            bool quoteOk = CheckQuoteOk(m3Received, m3QuoteStr, currentGaStr);
            if (!quoteOk)
            {
                log.Debug("Invalid Message 3 Quote");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            // Check whether using Debug quote or not
            bool debugCheck = CheckDebug(m3QuoteStr);
            if (!debugCheck)
            {
                log.Debug("Invalid Message 3 - Using Debug or Production quote when opposite is expected");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            // Check Signature Type
            bool sigTypeCheck = CheckSignatureType(m3QuoteStr);
            if (!sigTypeCheck)
            {
                log.Debug("Invalid Message 3 Signature");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            // Check ISV SVN
            bool isvSVNCheck = CheckISVSVN(m3QuoteStr);
            if (!isvSVNCheck)
            {
                log.Debug("Invalid Message 3 ISV SVN");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            // Successful
            // At this point, we know that a valid message 3 was received and we can send the quote to IAS.
            // Complete the state transition.
            M4ResponseMessage msg4Respsonse = new M4ResponseMessage();

            try
            {
                sigmaSequenceCheck.m3Received = true;
                Msg4Builder msgProcessor = new Msg4Builder();
                msg4Respsonse = await msgProcessor.BuildMessage4(sigmaSequenceCheck, m3Received);
            }
            catch (HttpRequestException re)
            {
                options.LogCaughtErrorException(re);
                log.Debug("Failed to create Message 4. " + re.Message);
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            log.Debug("ProcessMessage3(.) returning.");
            return msg4Respsonse;
        }

        /// <summary>
        /// Checks whether the received Message is the correct length or not
        /// Compare the reported length against the actual length (base16 string length/2)
        /// </summary>
        /// <param name="m3Received">Message 3 from client</param>
        /// <param name="m3ReceivedString">Message 3 as a string</param>
        /// <returns>Boolean of whether message length is correct</returns>
        private bool CheckMessageLength(M3RequestMessage m3Received, String m3ReceivedString)
        {
            log.Debug("CheckMessageLength(.) started.");

            if (m3Received == null || m3ReceivedString == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            bool correctLength = BitConverter.ToUInt32(m3Received.reqHeader.msgLength, 0) == (m3ReceivedString.Length / 2);

            if (!correctLength)
            {
                log.Debug("!!!                Length Check Error                    !!!");
            }

            log.DebugFormat("CheckMessageLength(.) returning {0}.", correctLength);
            return correctLength;
        }

        /// <summary>
        /// Determines whether Ga is correct
        /// ga from M3 should be the same ga as in M1.
        /// </summary>
        /// <param name="currentGaStr">ECC Ga String</param>
        /// <param name="m3GaStr">Message 3 ECC Ga String</param>
        /// <returns>Boolean whether the message string is as expected</returns>
        private bool CheckGa(String currentGaStr, String m3GaStr)
        {
            log.Debug("CheckGa(.) started.");

            if (currentGaStr == null || m3GaStr == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            bool gaCorrect = String.Equals(currentGaStr, m3GaStr, StringComparison.Ordinal);
            if (!gaCorrect)
            {
                log.Debug("!!!                 ga Mismatch Error                    !!!");
            }

            log.DebugFormat("CheckGa(.) returning {0}.", gaCorrect);
            return gaCorrect;
        }

        /// <summary>
        /// Checks whether the CMAC is valid and correct or not
        /// </summary>
        /// <param name="m3Received">Message 3 from client</param>
        /// <param name="m3GaStr">Message 3 ECC Ga String</param>
        /// <param name="sigmaSequenceCheck">Service Provider Sequence (State) Check</param>
        /// <returns>Boolean whether the CMAC was correct</returns>
        private bool CheckCmac(M3RequestMessage m3Received, String m3GaStr)
        {
            log.Debug("CheckCmac(.) started.");

            if (m3Received == null || m3GaStr == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // The received CMAC should match a computed CMAC
            string m3PsSecPropStr = bMessage.BaToBlobStr(m3Received.reqM3Body.secProperty);
            string m3QuoteStr = bMessage.BaToBlobStr(m3Received.reqM3Body.quote);
            string m3CmacBlobStr = m3GaStr + m3PsSecPropStr + m3QuoteStr;
            byte[] m3CmacBlobBa = bMessage.BlobStrToBa(m3CmacBlobStr);

            // Calculate the m3 CMAC value
            byte[] m3CmacSmk = cmacAES.Value(sigmaSequenceCheck.currentSmk, m3CmacBlobBa);
            string calcM3CmacSmkStr = bMessage.BaToBlobStr(m3CmacSmk);
            string m3aesCmacStr = bMessage.BaToBlobStr(m3Received.reqM3Body.aesCmac);

            bool cmacCorrect = String.Equals(m3aesCmacStr, calcM3CmacSmkStr, StringComparison.Ordinal);
            if (!cmacCorrect)
            {
                log.Debug("!!! CMAC Check Failure !!!");
            }

            log.DebugFormat("CheckCmac(.) returning {0}.", cmacCorrect);
            return cmacCorrect;
        }

        /// <summary>
        /// Checks whether to use Debug or not
        /// </summary>
        /// <param name="m3QuoteStr">Message 3 Quote String</param>
        /// <returns>Boolean whether the quote was debug version or not, and is valid</returns>
        private bool CheckDebug(String m3QuoteStr)
        {
            log.Debug("CheckDebug(.) started.");

            if (m3QuoteStr == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            bool debugCheck = true;
            Constants.QuoteInfo.Attributes = bMessage.BlobStrToBa(m3QuoteStr.Substring((int)Constants.QuoteInfo.AttributesOffset * 2, Constants.QuoteInfo.AttributesSize * 2));
            var DebugAttr = Constants.QuoteInfo.Attributes[0] & 0x2;

            // Check whether we have a debug or real enclave
            if (DebugAttr != 0)
            {
                log.Debug("Debug enclave found");
                if (sigmaSequenceCheck.enclaveType.IsProductionEnclave)
                {
                    debugCheck = false;
                    log.Debug("But production enclave expected -- don't proceed");
                }
                else    // Ensure that debug key gets sent to client
                    System.Buffer.BlockCopy(Constants.isvDebugKey, 0, Constants.isvKey, 0, Constants.isvDebugKey.Length);
            }
            else
            {
                log.Debug("Production enclave found");
                if (!sigmaSequenceCheck.enclaveType.IsProductionEnclave)
                {
                    debugCheck = false;
                    log.Debug("But debug enclave expected  -- don't proceed");
                }
            }

            log.DebugFormat("CheckDebug(.) returning {0}.", debugCheck);
            return debugCheck;
        }


        /// <summary>
        /// Check that the Quote is correct
        /// </summary>
        /// <param name="m3Received">Message 3 from client</param>
        /// <param name="m3QuoteStr">Message 3 quote string</param>
        /// <param name="sigmaSequenceCheck">Service Provider Sequence (State) Check</param>
        /// <param name="currentGaStr">Message 3 ECC Ga String</param>
        /// <returns>Boolean whether the provided quote was valid</returns>
        private bool CheckQuoteOk(M3RequestMessage m3Received, String m3QuoteStr, String currentGaStr)
        {
            log.Debug("CheckQuoteOk(.) started.");

            if (m3Received == null || m3QuoteStr == null || currentGaStr == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // The Quote should match a pre-provisioned enclave measurement, and the quote signature should be valid.
            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

            // Ensure quote is within defined range
            bool qSizeLimits = (m3Received.reqM3Body.quote.Length > MsgFieldLimits.UINT32_MINIMUM_QUOTE_SIZE && m3Received.reqM3Body.quote.Length < MsgFieldLimits.UINT32_PRACTICAL_SIZE_LIMIT);
            if (!qSizeLimits)
            {
                log.Debug("Quote size is invalid: " + m3Received.reqM3Body.quote.Length + ". Expected range: " + MsgFieldLimits.UINT32_MINIMUM_QUOTE_SIZE + " to " + MsgFieldLimits.UINT32_PRACTICAL_SIZE_LIMIT);
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.BadRequest);
                options.LogThrownException(e);
                throw e;
            }

            // Look at the enclave measurement stored in Constants.QuoteInfo from the settings file.
            // Assume the measurement is stored as a base 16 encoded string, but verify the input.
            bool qMeasurementMatch = false;
            bool qMeasurementRequired = false;

            string mrEncString = m3QuoteStr.Substring((int)Constants.QuoteInfo.mrEncOffset * 2, Constants.QuoteInfo.mrEncSize * 2);     // MR Enclave String from Quote

            log.DebugFormat("m3 quote measurement:         {0}", mrEncString);
            log.DebugFormat("recorded quote measurement:   {0}", sigmaSequenceCheck.enclaveType.MRENCLAVE);

            // Check the stored quote string from user input by attempting to convert to byte array form.
            if (!String.IsNullOrEmpty(sigmaSequenceCheck.enclaveType.MRENCLAVE))
            {
                qMeasurementRequired = true;
                byte[] mrEnclaveTestBa = bMessage.BlobStrToBa(sigmaSequenceCheck.enclaveType.MRENCLAVE);

                // Convert the MRenclave byte array back to string form to ensure uniform base16 Encoding from user input
                sigmaSequenceCheck.enclaveType.MRENCLAVE = bMessage.BaToBlobStr(mrEnclaveTestBa);
                qMeasurementMatch = String.Equals(mrEncString, sigmaSequenceCheck.enclaveType.MRENCLAVE, StringComparison.Ordinal);
                log.DebugFormat("converted quote measurement:  {0}", sigmaSequenceCheck.enclaveType.MRENCLAVE);
                log.DebugFormat("quote compare result:  {0}", qMeasurementMatch);
            }

            // Derive the "VK" key using VK = AES-CMAC(KDK, 0x01||’VK’||0x00||0x80 ||0x00)
            byte[] VK = bMessage.KeyLabelToKey(Constants.VK, sigmaSequenceCheck.currentKDK);

            // Compute a SHA-256 hash of (ga||gb||VK).
            string currentGbStr = bMessage.BaToBlobStr(sigmaSequenceCheck.currentGb);
            string vKstring = bMessage.BaToBlobStr(VK);
            string gabvkStr = currentGaStr + currentGbStr + vKstring;
            byte[] gabvkBa = bMessage.BlobStrToBa(gabvkStr);
            byte[] gabvkHashBa = null;

            // Klocwork issues related to qRptSha...
            // Klocwork thinks tha this object is dereferenced before null check.  However, if it is
            // null, then an exception is thrown below, outside of our try-catch-finally block, and
            // all other paths go through the try-catch-finally, where it gets properly disposed.
            // It appears that klocwork somehow became confused in this code flow.
            using (SHA256Cng qRptSha = new SHA256Cng())
            {
                if (qRptSha == null)
                {
                    HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                    options.LogThrownException(e);
                    throw e;
                }

                try
                {
                    gabvkHashBa = qRptSha.ComputeHash(gabvkBa);

                    string gabvkHashString = bMessage.BaToBlobStr(gabvkHashBa);

                    // Retrieve the non-zero (first 32) Bytes of the "REPORTDATA" field from the quote
                    string rptDataString = m3QuoteStr.Substring((int)Constants.QuoteInfo.reportDataOffset * 2, Constants.QuoteInfo.reportDataSize * 2);
                    bool qHashMatch = false;
                    log.DebugFormat("m3 (ga||gb||VK) hash:        {0}", rptDataString);
                    log.DebugFormat("computed (ga||gb||VK) hash:  {0}", gabvkHashString);
                    qHashMatch = String.Equals(rptDataString, gabvkHashString, StringComparison.Ordinal);
                    log.DebugFormat("hash compare result:  {0}", qHashMatch);

                    // Evaluate the quote check conditions
                    if (qSizeLimits && qHashMatch && (qMeasurementMatch || !qMeasurementRequired))
                    {
                        log.Debug("CheckQuoteOk(.) returning true.");
                        return true;
                    }

                    log.Debug("!!! Quote Check Failure !!!");
                    PrintQuote(m3QuoteStr);
                }
                catch (Exception e)
                {
                    options.LogCaughtErrorException(e);
                    log.Debug("Error checking Quote. " + e.Message);
                    HttpResponseException newException = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                    options.LogThrownException(newException);
                    throw newException;
                }
            }

            log.Debug("CheckQuoteOk(.) returning false.");
            return false;
        }

        /// <summary>
        /// Print Quote Failure String
        /// </summary>
        /// <param name="m3QuoteStr">Message 3 Quote String</param>
        private void PrintQuote(String m3QuoteStr)
        {
            // no null check on m3QuoteStr as it will just print null if that's the case anyway
            log.DebugFormat("m3 quote:  {0}", m3QuoteStr);
        }

        /// <summary>
        /// Checks the Signature Type of the quote
        /// </summary>
        /// <param name="m3QuoteStr">Message 3 Quote</param>
        /// <returns>Boolean whether the quote signature was valid or not</returns>
        private bool CheckSignatureType(String m3QuoteStr)
        {
            log.Debug("CheckSignatureType(.) started.");

            if (m3QuoteStr == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            Constants.QuoteInfo.SignatureType = bMessage.BlobStrToBa(m3QuoteStr.Substring((int)Constants.QuoteInfo.SignatureTypeOffset * 2, 4));
            bool SigTypeCheck = Constants.QuoteInfo.SignatureType[0] == Constants.sltype[0];
            log.DebugFormat("Signature Type:\t{0}", Constants.QuoteInfo.SignatureType[0]);
            log.DebugFormat("Expected value:\t{0}", Constants.sltype[0]);
            log.DebugFormat("Compare result:\t{0}", SigTypeCheck);

            log.DebugFormat("CheckSignatureType(.) returning {0}.", SigTypeCheck);
            return SigTypeCheck;
        }

        /// <summary>
        /// Determines whether to check the ISV SVN or not
        /// </summary>
        /// <param name="m3QuoteStr">Message 3 Quote</param>
        /// <returns>Boolean whether the SVN was valid or not</returns>
        private bool CheckISVSVN(String m3QuoteStr)
        {
            log.Debug("CheckISVSVN(.) started.");

            if (m3QuoteStr == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            ushort ISVSVN = (ushort)BitConverter.ToInt16(bMessage.BlobStrToBa(m3QuoteStr.Substring((int)Constants.QuoteInfo.ISVSVNOffset * 2, 4)), 0);
            bool ISVSVNCheck = ISVSVN >= sigmaSequenceCheck.enclaveType.ISVSVNMinLevel;
            log.DebugFormat("ISVSVN:\t\t\t\t{0}", ISVSVN);
            log.DebugFormat("Expected to be at least level:\t{0}", sigmaSequenceCheck.enclaveType.ISVSVNMinLevel);
            log.DebugFormat("Compare result:\t{0}", ISVSVNCheck);

            log.DebugFormat("CheckISVSVN(.) returning {0}.", ISVSVNCheck);
            return ISVSVNCheck;
        }
    }
}
