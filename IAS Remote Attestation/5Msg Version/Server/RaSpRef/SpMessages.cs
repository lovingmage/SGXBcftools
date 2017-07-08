//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RaSpRef
{

    ///////////////////////////////////////////////////////////////////////////
    //
    // Request Message Classes
    // (These are request messages sent from the client to the server.)
    //
    ///////////////////////////////////////////////////////////////////////////
    class ReqMsgHeader
    {
        public byte[] protocolVer { get; set; } //2 Bytes
        public readonly byte[] resrvd = { 0x00, 0x00 }; //2 Bytes
        public byte[] reqType { get; set; } //4 Bytes
        public byte[] msgLength { get; set; } //4 Bytes
        public byte[] nonce { get; set; } //16 Bytes
        //28 Bytes Total
    }

    class RequestMessage
    {
        public ReqMsgHeader reqHeader { get; set; }
        public RequestMessage()
        {
            reqHeader = new ReqMsgHeader();
        }
    }

    //
    //Setup specific request message container classes 
    //for our sigma "like" sequence
    class ProvisionRequestMessage : RequestMessage
    {
        public ProvisionRequestMessage()
        {
            //Constructor to populate an "empty" object with values that allow 
            //dection of missing fields after deserialization.
            reqHeader.protocolVer = MsgInitValues.DS_EMPTY_BA2;
            reqHeader.reqType = BitConverter.GetBytes((UInt32)enMsgType.raReserved);
            reqHeader.msgLength = BitConverter.GetBytes((UInt32)enDefaultLength.raDefaultEmptyLength);
            reqHeader.nonce = MsgInitValues.DS_ZERO_BA16;
        }
        public ProvisionRequestMessage(string request)
        {
            //Constructor for an actual request message
            //for use as a reference or for making a real request.
            reqHeader.protocolVer = MsgInitValues.PROTOCOL;
            reqHeader.reqType = BitConverter.GetBytes((UInt32)enMsgType.raProvisionReq);
            reqHeader.msgLength = BitConverter.GetBytes((UInt32)enDefaultLength.raDefaultPreqLength);
            reqHeader.nonce = MsgInitValues.DS_ZERO_BA16;
        }
        public string GetMsgString()
        {
            //Produce a base16 encoded representation of the message 
            //for debug and validation.
            string pstr = null;
            //generate a provisioning request string with calls to BitConverter
            pstr = BitConverter.ToString(this.reqHeader.protocolVer);
            pstr += BitConverter.ToString(this.reqHeader.resrvd);
            pstr += BitConverter.ToString(this.reqHeader.reqType);
            pstr += BitConverter.ToString(this.reqHeader.msgLength);
            if (this.reqHeader.nonce != null)
            {
                pstr += BitConverter.ToString(this.reqHeader.nonce);
            }
            pstr = pstr.Replace("-", "");
            return pstr;
        }
    }

    class ReqMsg0Body
    {
        public byte[] ExtGID { get; set; }  //4 Bytes
    }

    //
    //Setup specific request message container classes 
    //for our sigma "like" sequence
    class M0RequestMessage : RequestMessage
    {
        public ReqMsg0Body reqM0Body { get; set; }
        public M0RequestMessage()
        {
            //Constructor to populate an "empty" object with values that allow 
            //dection of missing fields after deserialization.
            reqHeader.protocolVer = MsgInitValues.DS_EMPTY_BA2;
            reqHeader.reqType = BitConverter.GetBytes((UInt32)enMsgType.raReserved);
            reqHeader.msgLength = BitConverter.GetBytes((UInt32)enDefaultLength.raDefaultEmptyLength);
            reqHeader.nonce = MsgInitValues.DS_ZERO_BA16;
        }
        public M0RequestMessage(string request)
        {
            //Constructor for an actual request message
            //for use as a reference or for making a real request.
            reqHeader.protocolVer = MsgInitValues.PROTOCOL;
            reqHeader.reqType = BitConverter.GetBytes((UInt32)enMsgType.raProvisionReq);
            reqHeader.msgLength = BitConverter.GetBytes((UInt32)enDefaultLength.raDefaultPreqLength);
            reqHeader.nonce = MsgInitValues.DS_ZERO_BA16;
        }
        public string GetMsgString()
        {
            //Produce a base16 encoded representation of the message 
            //for debug and validation.
            string m0str = null;
            //generate a provisioning request string with calls to BitConverter
            m0str = BitConverter.ToString(this.reqHeader.protocolVer);
            m0str += BitConverter.ToString(this.reqHeader.resrvd);
            m0str += BitConverter.ToString(this.reqHeader.reqType);
            m0str += BitConverter.ToString(this.reqHeader.msgLength);
            if (this.reqHeader.nonce != null)
            {
                m0str += BitConverter.ToString(this.reqHeader.nonce);
            }
            m0str += BitConverter.ToString(this.reqM0Body.ExtGID);
            m0str = m0str.Replace("-", "");
            return m0str;
        }
    }

    class ReqMsg1Body
    {
        public byte[] gaX { get; set; }  //32 Bytes
        public byte[] gaY { get; set; }  //32 Bytes
        public byte[] pltfrmGid { get; set; }  //4 Bytes
    }

    class M1RequestMessage : RequestMessage
    {
        public ReqMsg1Body reqM1Body { get; set; }
        public M1RequestMessage()
        {
            //Constructor to populate an "empty" object with values that allow 
            //dection of missing fields after deserialization.
            reqHeader.protocolVer = MsgInitValues.DS_EMPTY_BA2;
            reqHeader.reqType = BitConverter.GetBytes((UInt32)enMsgType.raReserved);
            reqHeader.msgLength = BitConverter.GetBytes((UInt32)enDefaultLength.raDefaultEmptyLength);
            reqHeader.nonce = MsgInitValues.DS_ZERO_BA16;
            reqM1Body = new ReqMsg1Body();
            reqM1Body.gaX = MsgInitValues.DS_EMPTY_BA32;
            reqM1Body.gaY = MsgInitValues.DS_EMPTY_BA32;
            reqM1Body.pltfrmGid = MsgInitValues.DS_EMPTY_BA32;
        }
        public M1RequestMessage(string request)
        {
            //Constructor for an actual request message
            //for use as a reference or for making a real request.
            reqHeader.protocolVer = MsgInitValues.PROTOCOL;
            reqHeader.reqType = BitConverter.GetBytes((UInt32)enMsgType.raMessage1Req);
            reqHeader.msgLength = BitConverter.GetBytes((UInt32)enDefaultLength.raDefaultM1Length);
            reqHeader.nonce = MsgInitValues.DS_ZERO_BA16;
            reqM1Body = new ReqMsg1Body();
        }
        public string GetMsgString()
        {
            //Produce a base16 encoded representation of the message 
            //for debug and validation.
            string m1str = null;
            //
            //Use BitConverter to produce a base16 encoded output string
            m1str = BitConverter.ToString(this.reqHeader.protocolVer);
            m1str += BitConverter.ToString(this.reqHeader.resrvd);
            m1str += BitConverter.ToString(this.reqHeader.reqType);
            m1str += BitConverter.ToString(this.reqHeader.msgLength);
            if (this.reqHeader.nonce != null)
            {
                m1str += BitConverter.ToString(this.reqHeader.nonce);
            }
            if (this.reqM1Body.gaX != null && this.reqM1Body.gaY != null)
            {
                m1str += BitConverter.ToString(this.reqM1Body.gaX);
                m1str += BitConverter.ToString(this.reqM1Body.gaY);
            }
            m1str += BitConverter.ToString(this.reqM1Body.pltfrmGid);
            m1str = m1str.Replace("-", "");
            return m1str;
        }
        public string GetGaString()
        {
            string gaStr = null;
            if (this.reqM1Body.gaX != null && this.reqM1Body.gaY != null)
            {
                gaStr = BitConverter.ToString(this.reqM1Body.gaX);
                gaStr += BitConverter.ToString(this.reqM1Body.gaY);
            }

            if (gaStr != null)
                gaStr = gaStr.Replace("-", "");

            return gaStr;
        }
    }

    class ReqMsg3Body
    {
        public byte[] aesCmac { get; set; }
        public byte[] gaX { get; set; }
        public byte[] gaY { get; set; }
        public byte[] secProperty { get; set; }
        public byte[] quote { get; set; }
    }

    class M3RequestMessage : RequestMessage
    {
        public ReqMsg3Body reqM3Body { get; set; }
        public M3RequestMessage()
        {
            //Constructor to populate an "empty" object with values that allow 
            //dection of missing fields after deserialization.
            reqHeader.protocolVer = MsgInitValues.DS_EMPTY_BA2;
            reqHeader.reqType = BitConverter.GetBytes((UInt32)enMsgType.raReserved);
            reqHeader.msgLength = BitConverter.GetBytes((UInt32)enDefaultLength.raDefaultEmptyLength);
            reqHeader.nonce = MsgInitValues.DS_ZERO_BA16;
            reqM3Body = new ReqMsg3Body();
            reqM3Body.aesCmac = MsgInitValues.DS_ZERO_BA16;
            reqM3Body.gaX = MsgInitValues.DS_EMPTY_BA32;
            reqM3Body.gaY = MsgInitValues.DS_EMPTY_BA32;
            reqM3Body.secProperty = MsgInitValues.DS_EMPTY_BA256;
            reqM3Body.quote = MsgInitValues.DS_EMPTY_BA64;
        }
        public M3RequestMessage(string request)
        {
            //Constructor for an actual request message
            //for use as a reference or for making a real request.
            reqHeader.protocolVer = MsgInitValues.PROTOCOL;
            reqHeader.reqType = BitConverter.GetBytes((UInt32)enMsgType.raMessage3Req);
            reqHeader.msgLength = BitConverter.GetBytes((UInt32)enDefaultLength.raDefaultM3Length);
            reqHeader.nonce = MsgInitValues.DS_ZERO_BA16;
            reqM3Body = new ReqMsg3Body();
        }
        public string GetMsgString()
        {
            //Produce a base16 encoded representation of the message 
            //for debug and validation.
            string m3str = null;
            //
            //Use BitConverter to produce a base16 encoded output string
            m3str = BitConverter.ToString(this.reqHeader.protocolVer);
            m3str += BitConverter.ToString(this.reqHeader.resrvd);
            m3str += BitConverter.ToString(this.reqHeader.reqType);
            m3str += BitConverter.ToString(this.reqHeader.msgLength);
            if (this.reqHeader.nonce != null && this.reqM3Body.aesCmac != null
                && this.reqM3Body.gaX != null && this.reqM3Body.gaY != null &&
                this.reqM3Body.secProperty != null && this.reqM3Body.quote != null)
            {
                m3str += BitConverter.ToString(this.reqHeader.nonce);
                m3str += BitConverter.ToString(this.reqM3Body.aesCmac);
                m3str += BitConverter.ToString(this.reqM3Body.gaX);
                m3str += BitConverter.ToString(this.reqM3Body.gaY);
                m3str += BitConverter.ToString(this.reqM3Body.secProperty);
                m3str += BitConverter.ToString(this.reqM3Body.quote);
            }
            m3str = m3str.Replace("-", "");
            return m3str;
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    //
    // Response Message Classes
    // (These are response messages sent from the server to the client.)
    //
    ///////////////////////////////////////////////////////////////////////////
    class ResponseMsgHeader
    {
        public byte[] protocolVer { get; set; } //2 Bytes
        public readonly byte[] reserved = { 0x00, 0x00 }; //2 Bytes
        public byte[] respStatus { get; set; }
        public byte[] respType { get; set; }
        public byte[] msgLength { get; set; }
        public byte[] sessionNonce { get; set; }
        //32 Bytes Total
    }

    class ResponseMessage
    {
        public ResponseMsgHeader respHeader { get; set; }
        public ResponseMessage()
        {
            respHeader = new ResponseMsgHeader();
        }
    }

    class ResponseChallengeMsgBody
    {
        //The Challenge message body is 16Bytes, zero filled.
        public readonly byte[] reserved = MsgInitValues.DS_ZERO_BA16;
    }

    class ChallengeResponse : ResponseMessage
    {
        public ResponseChallengeMsgBody cRespBody { get; set; }
        public ChallengeResponse()
        {
            //Constructor to populate an "empty" object
            respHeader.protocolVer = MsgInitValues.DS_EMPTY_BA2;
            respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrUnknown);
            respHeader.respType = BitConverter.GetBytes((UInt32)enMsgType.raReserved);
            respHeader.msgLength = BitConverter.GetBytes((UInt32)enDefaultLength.raDefaultEmptyLength);
            respHeader.sessionNonce = MsgInitValues.DS_ZERO_BA16;
            cRespBody = new ResponseChallengeMsgBody();
        }
        public ChallengeResponse(string respond)
        {
            respHeader.protocolVer = MsgInitValues.PROTOCOL;
            respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrNone);
            respHeader.respType = BitConverter.GetBytes((UInt32)enMsgType.raChallengeResp);
            respHeader.msgLength = BitConverter.GetBytes((UInt32)enDefaultLength.raDefaultCrespLength);
            respHeader.sessionNonce = MsgInitValues.DS_ZERO_BA16;
            cRespBody = new ResponseChallengeMsgBody();
        }
        public string GetMsgString()
        {
            //Produce a base16 encoded representation of the message 
            //for debug and validation.
            string cRespStr = null;
            //
            //generate a challenge message response string with BitConverter
            cRespStr = BitConverter.ToString(this.respHeader.protocolVer);
            cRespStr += BitConverter.ToString(this.respHeader.reserved);
            cRespStr += BitConverter.ToString(this.respHeader.respStatus);
            cRespStr += BitConverter.ToString(this.respHeader.respType);
            cRespStr += BitConverter.ToString(this.respHeader.msgLength);
            cRespStr += BitConverter.ToString(this.respHeader.sessionNonce);
            cRespStr += BitConverter.ToString(this.cRespBody.reserved);
            cRespStr = cRespStr.Replace("-", "");
            return cRespStr;
        }
    }

    class M0ResponseMessage : ResponseMessage
    {
        public M0ResponseMessage()
        {
            //Constructor to populate an "empty" object  
            respHeader.protocolVer = MsgInitValues.PROTOCOL;
            respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrNone);
            respHeader.respType = BitConverter.GetBytes((UInt32)enMsgType.raMessage0Resp);
            respHeader.msgLength = BitConverter.GetBytes((UInt32)enDefaultLength.raDefaultM0RespLength);
            respHeader.sessionNonce = MsgInitValues.DS_ZERO_BA16;
        }
        public string GetMsgString()
        {
            //Produce a base16 encoded representation of the message 
            //for debug and validation.
            string m0str = null;
            //Use BitConverter to produce a base16 encoded Msg2 output string
            m0str = BitConverter.ToString(this.respHeader.protocolVer);
            m0str += BitConverter.ToString(this.respHeader.reserved);
            m0str += BitConverter.ToString(this.respHeader.respStatus);
            m0str += BitConverter.ToString(this.respHeader.respType);
            m0str += BitConverter.ToString(this.respHeader.msgLength);
            m0str += BitConverter.ToString(this.respHeader.sessionNonce);
            m0str = m0str.Replace("-", "");
            return m0str;
        }
    }

    class ResponseM2Body
    {
        public byte[] gbX { get; set; }
        public byte[] gbY { get; set; }
        public byte[] spId { get; set; }
        public byte[] sigLinkType { get; set; }
        public byte[] kdfId { get; set; }
        public byte[] sigSpX { get; set; }
        public byte[] sigSpY { get; set; }
        public byte[] cmacsmk { get; set; }
        public byte[] sigrlSize { get; set; }
        public byte[] sigRl { get; set; }
    }

    class M2ResponseMessage : ResponseMessage
    {
        public ResponseM2Body respMsg2Body { get; set; }
        public M2ResponseMessage()
        {
            //Constructor to populate an "empty" object  
            respHeader.protocolVer = MsgInitValues.DS_EMPTY_BA2;
            respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrUnknown);
            respHeader.respType = BitConverter.GetBytes((UInt32)enMsgType.raReserved);
            respHeader.msgLength = BitConverter.GetBytes((UInt32)enDefaultLength.raDefaultEmptyLength);
            respHeader.sessionNonce = MsgInitValues.DS_ZERO_BA16;
            respMsg2Body = new ResponseM2Body();
            respMsg2Body.gbX = MsgInitValues.DS_EMPTY_BA32;
            respMsg2Body.gbY = MsgInitValues.DS_EMPTY_BA32;
            respMsg2Body.spId = MsgInitValues.DS_ZERO_BA16;
            respMsg2Body.sigLinkType = MsgInitValues.DS_EMPTY_BA2;
            respMsg2Body.kdfId = MsgInitValues.DS_EMPTY_BA2;
            respMsg2Body.sigSpX = MsgInitValues.DS_EMPTY_BA32;
            respMsg2Body.sigSpY = MsgInitValues.DS_EMPTY_BA32;
            respMsg2Body.cmacsmk = MsgInitValues.DS_ZERO_BA16;
            respMsg2Body.sigrlSize = MsgInitValues.DS_EMPTY_BA4;
            respMsg2Body.sigRl = null;
        }
        public M2ResponseMessage(string respond)
        {
            respHeader.protocolVer = MsgInitValues.PROTOCOL;
            respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrNone);
            respHeader.respType = BitConverter.GetBytes((UInt32)enMsgType.raMessage2Resp);
            respHeader.msgLength = BitConverter.GetBytes((UInt32)enDefaultLength.raDefaultM2Length);
            respHeader.sessionNonce = MsgInitValues.DS_ZERO_BA16;
            respMsg2Body = new ResponseM2Body();
        }
        public string GetMsgString()
        {
            //Produce a base16 encoded representation of the message 
            //for debug and validation.
            string m2str = null;
            //Use BitConverter to produce a base16 encoded Msg2 output string
            m2str = BitConverter.ToString(this.respHeader.protocolVer);
            m2str += BitConverter.ToString(this.respHeader.reserved);
            m2str += BitConverter.ToString(this.respHeader.respStatus);
            m2str += BitConverter.ToString(this.respHeader.respType);
            m2str += BitConverter.ToString(this.respHeader.msgLength);
            m2str += BitConverter.ToString(this.respHeader.sessionNonce);
            m2str += BitConverter.ToString(this.respMsg2Body.gbX);
            m2str += BitConverter.ToString(this.respMsg2Body.gbY);
            m2str += BitConverter.ToString(this.respMsg2Body.spId);
            m2str += BitConverter.ToString(this.respMsg2Body.sigLinkType);
            m2str += BitConverter.ToString(this.respMsg2Body.kdfId);
            m2str += BitConverter.ToString(this.respMsg2Body.sigSpX);
            m2str += BitConverter.ToString(this.respMsg2Body.sigSpY);
            m2str += BitConverter.ToString(this.respMsg2Body.cmacsmk);
            m2str += BitConverter.ToString(this.respMsg2Body.sigrlSize);
            //Include only a non-null sigRL
            if (this.respMsg2Body.sigRl != null)
            {
                m2str += BitConverter.ToString(this.respMsg2Body.sigRl);
            }
            m2str = m2str.Replace("-", "");
            return m2str;
        }
    }
    class ResponseM4Body
    {
        public byte[] platformInfo { get; set; }
        public readonly byte[] pltfrmInfoRsrvd = new byte[3] { 0x00, 0x00, 0x00 };
        public byte[] attestationStatus { get; set; }
        public byte[] cmacStatus { get; set; }
        public byte[] isvCryptPayloadSize { get; set; }
        public byte[] isvClearPayloadSize { get; set; }
        public byte[] CryptIv { get; set; }
        public byte[] isvPayloadTag { get; set; }
        public byte[] isvPayload { get; set; }
    }
    class M4ResponseMessage : ResponseMessage
    {
        public ResponseM4Body respMsg4Body { get; set; }

        public M4ResponseMessage()
        {
            //Constructor to populate an "empty" object
            respHeader.protocolVer = MsgInitValues.PROTOCOL;
            respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrUnknown);
            respHeader.respType = BitConverter.GetBytes((UInt32)enMsgType.raReserved);
            respHeader.msgLength = BitConverter.GetBytes((UInt32)enDefaultLength.raDefaultEmptyLength);
            respHeader.sessionNonce = MsgInitValues.DS_EMPTY_NONCE;
            respMsg4Body = new ResponseM4Body();
            respMsg4Body.platformInfo = null;
            //m4Body.pltfrmInfoRsrvd handled by instantiation
            respMsg4Body.attestationStatus = MsgInitValues.DS_EMPTY_BA4;
            respMsg4Body.cmacStatus = MsgInitValues.DS_ZERO_BA16;
            respMsg4Body.isvCryptPayloadSize = MsgInitValues.DS_ZERO_BA4;
            respMsg4Body.isvClearPayloadSize = MsgInitValues.DS_ZERO_BA4;
            respMsg4Body.CryptIv = null;
            respMsg4Body.isvPayloadTag = null;
            respMsg4Body.isvPayload = null;
        }

        public M4ResponseMessage(string respond)
        {
            respHeader.protocolVer = MsgInitValues.PROTOCOL;
            respHeader.respStatus = BitConverter.GetBytes((UInt32)enStatusCodes.raErrNone);
            respHeader.respType = BitConverter.GetBytes((UInt32)enMsgType.raIsvPayloadResp);
            respHeader.msgLength = BitConverter.GetBytes((UInt32)enDefaultLength.raDefaultM4Length);
            respHeader.sessionNonce = MsgInitValues.DS_ZERO_BA16;
            respMsg4Body = new ResponseM4Body();
        }

        public string GetMsgString()
        {
            //Produce a base16 encoded representation of the message 
            //for debug and validation.
            string m4str = null;
            //Use BitConverter to produce a base16 encoded output string
            m4str = BitConverter.ToString(this.respHeader.protocolVer);
            m4str += BitConverter.ToString(this.respHeader.reserved);
            m4str += BitConverter.ToString(this.respHeader.respStatus);
            m4str += BitConverter.ToString(this.respHeader.respType);
            m4str += BitConverter.ToString(this.respHeader.msgLength);
            m4str += BitConverter.ToString(this.respHeader.sessionNonce);
            if (this.respMsg4Body.platformInfo != null)
                m4str += BitConverter.ToString(this.respMsg4Body.platformInfo);
            m4str += BitConverter.ToString(this.respMsg4Body.pltfrmInfoRsrvd);
            m4str += BitConverter.ToString(this.respMsg4Body.attestationStatus);
            m4str += BitConverter.ToString(this.respMsg4Body.cmacStatus);
            m4str += BitConverter.ToString(this.respMsg4Body.isvCryptPayloadSize);
            m4str += BitConverter.ToString(this.respMsg4Body.isvClearPayloadSize);
            if (this.respMsg4Body.CryptIv != null)
                m4str += BitConverter.ToString(this.respMsg4Body.CryptIv);
            if (this.respMsg4Body.isvPayloadTag != null)
                m4str += BitConverter.ToString(this.respMsg4Body.isvPayloadTag);
            if (this.respMsg4Body.isvPayload != null)
                m4str +="\n\n"+ BitConverter.ToString(this.respMsg4Body.isvPayload);
            m4str = m4str.Replace("-", "");
            return m4str;
        }
    }
}
