//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using IppDotNetWrapper;
using log4net;
using System.Reflection;
using SgxOptions;

namespace RaSpRef
{
    //Container Class for methods and properties related to message construction
    class BuildMessage
    {

        private static SpCmacAes cmacAES = new SpCmacAes();

        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);

        // method to convert an arbitrary blob in hex string form to a byte array, assuming a hex string input 
        // as in "ACF00458".
        public string BaToBlobStr(byte[] Ba)
        {
            return BitConverter.ToString(Ba).Replace("-", "");
        }

        public byte[] BlobStrToBa(string blobString)
        {
            if (blobString == null)
            {
                Exception e = new System.ArgumentNullException("blobString");
                options.LogThrownException(e);
                throw e;
            }

            // Convert a base 16 encoded blob string to an array of 8 bit bytes
            const int dwordBase = Constants.Base16;
            const int charsPerByte = Constants.CharsPerByte;
            int bAlength = blobString.Length / charsPerByte;
            var conglomerateBa = new byte[bAlength];
            // Since the input can be any string, check to see that we have base 16 characters
            if (blobString.Length > 0)
            {
                bool isBase16 = true;
                // assume all is well, but scan through the string for anything outside of base 16 encoding.
                foreach (Char cVal in blobString.ToUpper())
                {
                    if (!(cVal.Equals('A') || cVal.Equals('B') || cVal.Equals('C') || cVal.Equals('D') || cVal.Equals('E') || cVal.Equals('F') ||
                        cVal.Equals('0') || cVal.Equals('1') || cVal.Equals('2') || cVal.Equals('3') || cVal.Equals('4') || cVal.Equals('5') ||
                        cVal.Equals('6') || cVal.Equals('7') || cVal.Equals('8') || cVal.Equals('9')))
                    {
                        isBase16 = false;
                        log.DebugFormat("***** Error: Input character Not in Base16 Format:  \"{0}\"", cVal);
                    }
                }
                if (isBase16)
                {
                    for (int i = 0; i < bAlength; i++)
                    {
                        // interpret the string contents as base 16 (hex) data
                        int byteIndex = i * charsPerByte;
                        string byteString = blobString.Substring(byteIndex, charsPerByte);
                        conglomerateBa[i] = Convert.ToByte(byteString, dwordBase);
                    }
                    // assign the result reference to the output parameter
                    return conglomerateBa;
                }
                else
                {
                    log.Debug("***** Error:  One or more input characters is NOT in Base16 Format!");
                    return conglomerateBa;
                }
            }
            log.Debug("***** Error:  Cannot convert a NULL blob string!");
            return conglomerateBa;
        }

        public byte[] KeyLabelToKey(string label, byte[] KDK)
        {
            byte[] labelBa = Encoding.ASCII.GetBytes(label);
            string secFieldElementStr = "01" + BaToBlobStr(labelBa) + "008000";
            byte[] secFieldElement = BlobStrToBa(secFieldElementStr);
            byte[] key = cmacAES.Value(KDK, secFieldElement);
            return key;
        }

        
        //build a provisioning request message
        public void buildProvisioningRequest(out ProvisionRequestMessage pReq, out string oPvReqstr)
        {
            //A Provisioning Request is a request message header with a zero filled nonce field
            string request = Constants.Request;
            var provReq = new ProvisionRequestMessage(request);
            provReq.reqHeader.nonce = MsgInitValues.DS_ZERO_BA16;

            //copy each reference to its output parameter
            pReq = provReq;
            oPvReqstr = provReq.GetMsgString();
            return;
        }


        //Build a challenge response message
        public void buildChallengeResponse(out ChallengeResponse cMResp)
        {
            string respond = Constants.Respond;
            var cMsg = new ChallengeResponse(respond);

            //populate the message object with header and body components
            var cMsgBody = new ResponseChallengeMsgBody();

            cMsg.respHeader.sessionNonce = Constants.sn1;
            cMsg.cRespBody = cMsgBody;

            //assign a return object reference
            cMResp = cMsg;
            return;
        }


        //Build an M1 request
        public void buildM1Request(out M1RequestMessage m1Req)
        {
            string request = Constants.Request;

            var m1Msg = new M1RequestMessage(request);
            var m1Body = new ReqMsg1Body();
            m1Msg.reqHeader.nonce = Constants.sn1;
            m1Body.pltfrmGid = Constants.sampleGid;
            m1Body.gaX = Constants.sampleGaXba;
            m1Body.gaY = Constants.sampleGaYba;

            m1Msg.reqM1Body = m1Body;
            m1Req = m1Msg;
            return;
        }

        //Build an M2 response
        public void buildM2Response(out M2ResponseMessage m2Resp)
        {
            string respond = Constants.Respond;
            byte[] tempM2Bytes = { 0x00 };

            var m2Body = new ResponseM2Body();
            var m2Response = new M2ResponseMessage(respond);


            //Populate message body components
            m2Response.respMsg2Body.gbX = Constants.sampleGbXba;
            m2Response.respMsg2Body.gbY = Constants.sampleGbYba;
            m2Response.respMsg2Body.spId = SpStartup.iasConnectionMgr.SPID;
            m2Response.respMsg2Body.sigLinkType = Constants.sltype;
            m2Response.respMsg2Body.kdfId = Constants.kdfId;

            //the m2 slReserved field is automatically initialized in the instance
            m2Response.respMsg2Body.sigSpX = Constants.sigSpXba;
            m2Response.respMsg2Body.sigSpY = Constants.sigSpYba;

            using (RNGCryptoServiceProvider nonceGen = new RNGCryptoServiceProvider())
            {
                if (nonceGen == null)
                {
                    Exception e = new Exception("Internal Error: nonceGen is Null");
                    options.LogThrownException(e);
                    throw e;
                }

                byte[] sessionNonce = Constants.sn2;
                nonceGen.GetBytes(sessionNonce);  //Generate a new nonce
                m2Response.respMsg2Body.cmacsmk = sessionNonce;
                m2Response.respMsg2Body.sigrlSize = MsgInitValues.DS_EMPTY_BA4;
                m2Response.respMsg2Body.sigRl = null;

                //Copy each reference to its output parameter
                m2Resp = m2Response;
            }

            return;
        }

        //Build an M3 request
        public void buildM3Request(out M3RequestMessage m3Req)
        {
            string request = Constants.Request;
            var m3Msg = new M3RequestMessage(request);
            var m3Body = new ReqMsg3Body();
            m3Body.aesCmac = Constants.sampleCmacsmk;
            m3Body.gaX = Constants.sampleGaXba;
            m3Body.gaY = Constants.sampleGaYba;
            m3Body.secProperty = Constants.sampleM3secProp;
            m3Body.quote = Constants.sampleQuote;

            //load a complete message object
            m3Msg.reqM3Body = m3Body;
            m3Req = m3Msg;
            return;
        }

        //Buid an M4 response
        public void buildM4Response(out M4ResponseMessage m4Resp)
        {
            string respond = Constants.Respond;
            var m4Response = new M4ResponseMessage(respond);
            var m4Body = new ResponseM4Body();
            m4Body.platformInfo = null;

            //m4Body.pltfrmInfoRsrvd handled by instantiation
            m4Body.attestationStatus = MsgInitValues.DS_ZERO_BA4;
            m4Body.cmacStatus = MsgInitValues.DS_ZERO_BA16;
            m4Body.isvCryptPayloadSize = MsgInitValues.DS_ZERO_BA4;
            
            m4Body.isvClearPayloadSize = MsgInitValues.DS_ZERO_BA4;
            
            m4Body.CryptIv = null;
            m4Body.isvPayloadTag = null;
            m4Body.isvPayload = null;
            m4Response.respMsg4Body = m4Body;
            m4Resp = m4Response;
            return;
        }

    }

}
