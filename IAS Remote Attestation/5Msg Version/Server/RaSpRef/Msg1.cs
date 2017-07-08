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
    class Msg1
    {
        #region Vars
        string gidBaString = string.Empty;
        byte[] gaXBigEndian = new byte[Constants.GaGbLen];
        byte[] gaYBigEndian = new byte[Constants.GaGbLen];
        byte[] gaXLittleEndian = new byte[Constants.GaGbLen];
        byte[] gaYLittleEndian = new byte[Constants.GaGbLen];
        string gaXBigEndianstr = string.Empty;
        string gaYBigEndianstr = string.Empty;
        string gaXLittleEndianstr = string.Empty;
        string gaYLittleEndianstr = string.Empty;

        string gaLittleEndianstr = string.Empty;
        string gaBlobStr = string.Empty;
        byte[] gbXBigEndian = new byte[Constants.GaGbLen];
        byte[] gbYBigEndian = new byte[Constants.GaGbLen];
        byte[] gbXLittleEndian = new byte[Constants.GaGbLen];
        byte[] gbYLittleEndian = new byte[Constants.GaGbLen];
        string gbXBigEndianstr = string.Empty;
        string gbYBigEndianstr = string.Empty;
        string gbXLittleEndianstr = string.Empty;
        string gbYLittleEndianstr = string.Empty;

        byte[] sigSPXLittleEndian = new byte[Constants.GaGbLen];
        byte[] sigSPYLittleEndian = new byte[Constants.GaGbLen];
        byte[] cMACsmk = new byte[Constants.GaGbLen];

        string gbLittleEndianStr;
        string derivedKeyStr;
        #endregion

        private BuildMessage bMessage = new BuildMessage();
        private SpCmacAes cmacAES = new SpCmacAes();

        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);

        /// <summary>
        /// Process Message 1 and create Message 2
        /// </summary>
        /// <param name="Request">Client Provisioning request</param>
        /// <param name="sigmaSequenceCheck">Service Provider Sequence (State) Check</param>
        /// <returns>Message 2 content</returns>
        public M2ResponseMessage ProcessMessage1(HttpRequestMessage Request, SpSequenceCheck sigmaSequenceCheck)
        {
            log.Debug("ProcessMessage1(.) started.");

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

            // Check and parse Message 1
            M1RequestMessage m1Received = VerifyMessage1IsValid(Request, sigmaSequenceCheck);
            CalculateDiffieHellmanExchange(sigmaSequenceCheck, m1Received);

            // Successful process of Message 1
            // Create Message 2
            Msg2Builder msgProcessor = new Msg2Builder();
            M2ResponseMessage msg2Response = msgProcessor.BuildMessage2(sigmaSequenceCheck, m1Received, gidBaString, gbXLittleEndian, gbYLittleEndian, sigSPXLittleEndian, sigSPYLittleEndian, cMACsmk);
            log.Debug("ProcessMessage1(.) returning.");
            return msg2Response;
        }

        /// <summary>
        /// Verify that Message 1 is valid
        /// </summary>
        /// <param name="Request">Client Message 1 Response</param>
        /// <param name="sigmaSequenceCheck">Service Provider Sequence (State) Check</param>
        /// <returns>Parsed and validated Message 1</returns>
        private M1RequestMessage VerifyMessage1IsValid(HttpRequestMessage request, SpSequenceCheck sigmaSequenceCheck)
        {
            log.Debug("VerifyMessage1IsValid(.) started.");

            if (request == null || sigmaSequenceCheck == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // Update Client state
            if (!sigmaSequenceCheck.UpdateState(Constants.SequenceState.Msg1))
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.PreconditionFailed);
                options.LogThrownException(e);
                throw e;
            }

            // Check m1 and if valid, process, create a nonce, get the sigRL and return m2.
            // M1 = msg1 = m1 = s1 = ga||GID
            var result = request.Content.ReadAsStringAsync();
            string jsonMsg1Request = result.Result;

            M1RequestMessage m1Received = new M1RequestMessage();
            try
            {
                m1Received = JsonConvert.DeserializeObject<M1RequestMessage>(jsonMsg1Request);
            }
            catch (Exception msg1reqError)
            {
                options.LogCaughtErrorException(msg1reqError);
                log.DebugFormat("******* Message 1 JSON Content Error: {0}", msg1reqError);
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            string m1ReceivedString = m1Received.GetMsgString();
            log.Info("******* Received M1 Request");
            log.DebugFormat("{0}{1}", request.Headers, jsonMsg1Request);
            log.DebugFormat("M1 Base 16 Encoded String: {0}", m1ReceivedString);

            // Check the nonce and the base16 encoded length of the inbound request
            bool nonceCheckSuccess = false;
            try
            {
                log.Debug("Checking nonce");
                nonceCheckSuccess = sigmaSequenceCheck.currentNonce.SequenceEqual(m1Received.reqHeader.nonce);
            }
            catch (Exception e)
            {
                options.LogCaughtErrorException(e);
                log.DebugFormat("****Message 1 Nonce Error: {0}", e);
                HttpResponseException newException = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(newException);
                throw newException;
            }

            if (!nonceCheckSuccess)
            {
                log.Debug("Msg1 Nonce check failed");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            // Compare the reported length against the actual length (base16 string length/2)
            // Could BigEndian a replay attempt if the nonce field does not match. 
            // Could also be other tampering if other fields do not pass checks.
            // Restart the session, and reject the request.
            if (!(BitConverter.ToUInt32(m1Received.reqHeader.msgLength, 0) == (m1ReceivedString.Length / 2)))
            {
                log.Debug("Msg1 Message length check failed");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            if (m1Received.reqM1Body.gaX.SequenceEqual(MsgInitValues.DS_EMPTY_BA32))
            {
                log.Debug("Msg1 GaX check failed");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            if (m1Received.reqM1Body.gaY.SequenceEqual(MsgInitValues.DS_EMPTY_BA32))
            {
                log.Debug("Msg1 GaY check failed");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            if (m1Received.reqM1Body.pltfrmGid.SequenceEqual(MsgInitValues.DS_EMPTY_BA32))
            {
                log.Debug("Msg1 Platform Group ID check failed");
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.Forbidden);
                options.LogThrownException(e);
                throw e;
            }

            log.Debug("VerifyMessage1IsValid(.) returning.");
            return m1Received;
        }

        /// <summary>
        /// Calculate values for Diffie Hellman values 
        /// </summary>
        /// <param name="sigmaSequenceCheck">Service Provider Sequence (State) Check</param>
        /// <param name="m1Received">Message 1</param>
        private void CalculateDiffieHellmanExchange(SpSequenceCheck sigmaSequenceCheck, M1RequestMessage m1Received)
        {
            log.Debug("CalculateDiffieHellmanExchange(..) started.");

            if (sigmaSequenceCheck == null || m1Received == null)
            {
                HttpResponseException e = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(e);
                throw e;
            }

            // (Intel Performance Primitives) IPP Wrapper
            ippApiWrapper ippWrapper = new ippApiWrapper();

            // Process message 1 and build the message 2 response.
            // Capture the GID and Base16 encode the gid field per the IAS API specificaiton:   
            // "{gid} = Base 16-encoded representation of QE EPID group ID encoded as a Little Endian integer". 
            // NOTE: This conversion assumes that the GID was sent without modification in the "pltfrmGid" message field.

            byte[] gidBa = m1Received.reqM1Body.pltfrmGid;

            // Required that the GID is supplied with no conversions from the SGX client and reverse the byte order 
            // to convert to Big Endian integer for use later in the routine when encoding as a Base 16 string.
            Array.Reverse(gidBa);
            gidBaString = bMessage.BaToBlobStr(gidBa);

            // In crypto terms, a = Alice (Client) and b = Bob (Service provider)
            //  so ga = secret shared by client and gb = secret shared by service provide

            gaLittleEndianstr = m1Received.GetGaString();  // Received in Little Endian format

            gaXLittleEndianstr = "";
            // ga = gaX|gaY -- take the first half of ga to get gaX
            if (gaLittleEndianstr != null)
                gaXLittleEndianstr = gaLittleEndianstr.Substring(0, gaLittleEndianstr.Length / 2);

            gaXLittleEndian = bMessage.BlobStrToBa(gaXLittleEndianstr);
            gaXBigEndian = bMessage.BlobStrToBa(gaXLittleEndianstr);
            Array.Reverse(gaXBigEndian, 0, gaXBigEndian.Length);
            gaXBigEndianstr = bMessage.BaToBlobStr(gaXBigEndian);

            gaYLittleEndianstr = "";
            if (gaLittleEndianstr != null)
                gaYLittleEndianstr = gaLittleEndianstr.Substring(gaLittleEndianstr.Length / 2);

            gaYLittleEndian = bMessage.BlobStrToBa(gaYLittleEndianstr);
            gaYBigEndian = bMessage.BlobStrToBa(gaYLittleEndianstr);
            Array.Reverse(gaYBigEndian, 0, gaYBigEndian.Length);
            gaYBigEndianstr = bMessage.BaToBlobStr(gaYBigEndian);
            
            // Capture the Little Endian representation of ga for later message checking
            sigmaSequenceCheck.currentGa = bMessage.BlobStrToBa(gaXLittleEndianstr + gaYLittleEndianstr);
            {
                // Use IPP or some other alternative if the user configuration does not select MS bcrypt for Diffie-Hellman key exchange.                        
                // NOTE: The use of IPP allows for the use of the standard wrapper functions in the SGX SDK.
                log.Debug("Calling IPP Wrapper for Diffie-Hellman key exchange...");
                ippWrapper.InitDiffieHellman();
                ippWrapper.GetDHPublicKey(ref gbXLittleEndian, ref gbYLittleEndian);
                gbXLittleEndianstr = bMessage.BaToBlobStr(gbXLittleEndian);
                gbYLittleEndianstr = bMessage.BaToBlobStr(gbYLittleEndian);
                gbLittleEndianStr = string.Concat(gbXLittleEndianstr, gbYLittleEndianstr);
                sigmaSequenceCheck.currentGb = bMessage.BlobStrToBa(gbXLittleEndianstr + gbYLittleEndianstr);
                log.DebugFormat("Server Public key: {0}", gbLittleEndianStr);
                // Derive the shared key
                byte[] sharedKey256 = new byte[Constants.SharedKeylen];
                ippWrapper.GetDHSharedSecret(gaXLittleEndian, gaYLittleEndian, ref sharedKey256);
                derivedKeyStr = bMessage.BaToBlobStr(sharedKey256);
                log.DebugFormat("Shared secret: {0}", derivedKeyStr);
            }

            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // Use the full 256 bits of the derived DH key to further derive our smk
            //SMK is derived from the Diffie-Hellman shared secret elliptic curve field element
            // between the service provider and the
            // application enclave:
            // First compute Key Definition Key: KDK = AES-CMAC(0x00, gab x-coordinate)
            // Then SMK = AES-CMAC ( KDK, 0x01||’SMK’||0x00||0x80||0x00)

            byte[] derivedKeyBa = bMessage.BlobStrToBa(derivedKeyStr);
            // Store the KDK for further key derivation.
            sigmaSequenceCheck.currentKDK = cmacAES.Value(MsgInitValues.DS_ZERO_BA16, derivedKeyBa);
            // Store the SMK for the current session for use in processing message 3
            sigmaSequenceCheck.currentSmk = bMessage.KeyLabelToKey(Constants.SMK, sigmaSequenceCheck.currentKDK);

            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

            // Build each term by retrieving elements, 
            // concatenating, converting and performing crypto operations.
            string gbgaStr = gbXLittleEndianstr + gbYLittleEndianstr + gaXLittleEndianstr + gaYLittleEndianstr;
            byte[] gbgaBa = bMessage.BlobStrToBa(gbgaStr);          // gb||ga 

            // Sign the gb||ga element Service Provider -- we use sigSP to notate this Service Provider signature
            
            // Get the Private Key from the settings file
            byte[] privateKey;
            try
            {
                privateKey = Constants.spPrivKeyBlob;// spPrivKeyBlob;
            }
            catch (Exception e)
            {
                options.LogCaughtErrorException(e);
                log.Debug("Failed to get private key: " + e.Message);
                HttpResponseException newException = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(newException);
                throw newException;
            }

            CngKey signSgxKey = CngKey.Import(privateKey, CngKeyBlobFormat.EccPrivateBlob);
            ECDsaCng ecDsaSig = new ECDsaCng(signSgxKey);   // Elliptic Curve Digital Signature Algorithm, Signature
            ecDsaSig.HashAlgorithm = CngAlgorithm.Sha256;
            
            byte[] sigSPpubKey = ecDsaSig.Key.Export(CngKeyBlobFormat.EccPublicBlob);
            string sigSPpubKeyBlob = "{ 0x" + BitConverter.ToString(sigSPpubKey).Replace("-", ", 0x") + " }";
            byte[] sigSP = ecDsaSig.SignData(gbgaBa); // Input is LittleEndian, but output is BigEndian
            string sigSPstring = bMessage.BaToBlobStr(sigSP);

            // Separate the X and Y components of the signature -- Big Endian at this point
            string sigSPXBigEndianstr = sigSPstring.Substring(0, (sigSPstring.Length / 2));
            byte[] sigSPXBigEndian = bMessage.BlobStrToBa(sigSPXBigEndianstr);
            string sigSPYBigEndianstr = sigSPstring.Substring(sigSPstring.Length / 2);
            byte[] sigSPYBigEndian = bMessage.BlobStrToBa(sigSPYBigEndianstr);
            
            // Swap the byte order of the signed data back to Little Endian and convert to combined string (X|Y)
            sigSPXLittleEndian = sigSPXBigEndian.Reverse().ToArray();
            string sigSPXLittleEndianstr = bMessage.BaToBlobStr(sigSPXLittleEndian);
            sigSPYLittleEndian = sigSPYBigEndian.Reverse().ToArray();
            string sigSPYLittleEndianstr = bMessage.BaToBlobStr(sigSPYLittleEndian);
            string sigSPLittleEndianstring = sigSPXLittleEndianstr + sigSPYLittleEndianstr;
            // sigSPLittleEndianstring is in Little Endian format as required, ready to send to client

            // Get the signature link type
            try
            {
                if (SpStartup.iasConnectionMgr.LinkableQuotes)
                {
                    log.Debug("Using Linkable Quotes");
                    // If the SP policy setting dictates the use of linkable quotes, explicitly
                    // overwrite the default value in the sltype container.
                    // Otherwise, the default value will be an un-linkable quote type.
                    System.Buffer.BlockCopy(Constants.linkableBa, 0, Constants.sltype, 0, Constants.linkableBa.Length);
                }
            }
            catch (Exception e)
            {
                options.LogCaughtErrorException(e);
                log.Debug("Failed to get Linked Quote: " + e.Message);
                HttpResponseException newException = new HttpResponseException(System.Net.HttpStatusCode.InternalServerError);
                options.LogThrownException(newException);
                throw newException;
            }

            string sigTypeStr = bMessage.BaToBlobStr(Constants.sltype);
            string kdfIdStr = bMessage.BaToBlobStr(Constants.kdfId);
            string gbSpidSigSPstring = gbLittleEndianStr + bMessage.BaToBlobStr(SpStartup.iasConnectionMgr.SPID) + sigTypeStr + kdfIdStr + sigSPLittleEndianstring;
            byte[] macBlob = bMessage.BlobStrToBa(gbSpidSigSPstring);

            // Compute the CMAKsmk of (gb||SPID||Type||KDF-ID||SigSP(gb||ga))
            cMACsmk = cmacAES.Value(sigmaSequenceCheck.currentSmk, macBlob);
            string cMACsmkStr = bMessage.BaToBlobStr(cMACsmk);

            ecDsaSig.Dispose();

            log.Debug("CalculateDiffieHellmanExchange(..) returning.");
        }

    }
}
