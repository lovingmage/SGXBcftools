//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

/**************************************************************************************************
FILENAME:       RaMessages.h
DESCRIPTION:    Header file for RaMessages.cpp, defining Remote attesttaion
Request and Response Message types, related constants, initializers,utility functions
FUNCTIONALITY:  Defines enumerations for Message types,Default message length values,
error status codes,attestaion status codes,revocation reason codes,
pse manifest status codes used in the sigma protocol;
Different Message structures (Provision request, challenge response,M0, M1, M2, M3, M4) definitions;
******************************************************************************************************/
#ifndef RaMessages_h
#define RaMessages_h
#include <cpprest/http_client.h> // to support HTTP service
#include <cpprest/json.h>       // to support JSON Serialization and deserialization
#include <cstdint>             // to support uint16_t, uint32_t,..
#include <iomanip>             //to support setw()
#include <sgx_key_exchange.h>  // to support sgx_ra_msg2_t and sgx_ra_msg3_t
#include <iostream>			// to support std I/O stream objects (cout)
#include <sstream>          // to support string stream classes (ostringstream)
#include <string.h>        // to support string type 
typedef uint8_t uint8BYTE;

//Enumeration for different message types
enum enMsgType : uint32_t{
	RaReserved = 0x100,                 // 100, Reserved for testing or future use 
	RaProvisionReq = 0x101,             // 101, Provisioning Request from ISV app
	RaChallengeResp = 0x102,            // 102, Challenge Response from RA server
	RaMessage0Req = 0x103,              //Message 0 from ISV APP
	RaMessage0Resp = 0x104,              //Message0 from RA server
	RaMessage1Req = 0x105,              // 103, Msg1 from ISV app
	RaMessage2Resp = 0x106,             // 104, Msg2 from RA server
	RaMessage3Req = 0x107,              // 105, Msg3 from ISV app
	RaIsvPaylodResp = 0x108             // 106, ISV Payload Response message from RA server
};

// enumeration for default message length values used in the Messaage constructors
enum enDefaultLength : uint32_t{
	RaDefaultPreqLength = 0x1C,          // Provisioning Request from ISV app
	RaDefaultCrespLength = 0x30,         // Challenge Response from RA server
	RaDefaultM0ReqLength = 0x20,         //M0 from ISV-App
	RaDefaultM0RespLength = 0x20,        //M0 from RA server
	RaDefaultM1Length = 0x60,            // Msg1 from ISV app
	RaDefaultM2Length = 0xC8,           // Msg2 from RA server
	RaDefaultM3Length = 0x5D0,           // Msg3 from ISV app
	RaDefaultM4Length = 0xC4,            // ISV Payload Response message from RA server
	RaDefaultEmptyLength = 0xFFF,    // For deserialization validation
	RaDefaultQuoteLength = 1116           //Default quote length
};

//Enumeration for various possible ErrorStatus codes during the RA process
enum enStatusCodes : uint32_t{
	RaErrNone = 0x00,                    // 00, Success
	RaErrReqRejected = 0x01,             // 01, External error, ALL  - request message was rejected
	RaErrInternal = 0x02,                // 03, Internal error, for debug only
	RaErrUnknown = 0x03,                // 04, Internal error, a handshake error that is not expected.
	RaErrMeasurement = 0x10,             // 10, Enclave measurement mismatch error from SP RA server
	RaErrKeyCheckFail = 0x11,            // 11, SP RA server error checking ga in Msg3
	RaErrCmacCheckFail = 0x12,           // 12, SP RA server error checking CMACsmk in Msg3
	RaErrQuoteCheckFail = 0x13,          // 13, SP RA server error checking Quote in Msg3
	RaErrREPORTDATACheckFail = 14,       // 14, SP RA server error checking REPORTDATA field for Msg3 replay
	RaErrVerificationSigCheckFail = 15,  // 15, SP RA server error checking verification report signature from IAS
	RaErrIasGetSuccess = 0xC8,           // C8, (decimal 200) GET Operation success from IAS
	RaErrIasCreated = 0xC9,              // C9, (decimal 201) Create Report successful from IAS
	RaErrIasBadRequest = 190,            // 190, (decimal 400) Invalid Evidence Payload from IAS
	RaErrIasUnauth = 0x191,              // 191, (decimal 401) Unauthorized response from IAS
	RaErrIasNotFound = 0x194,            // 194, (decimal 404) Not Found response from IAS
	RaErrIasInternal = 0x1F4,            // 1F4, (decimal 500) Internal Error from IAS
	RaErrIasUnknown = 0x208              // 208, (decimal 520) Unknown IAS Error or Connection Error
};
extern void AbortProcess();

/* default Initialiation values used by different fields
*/
class MsgInitValues{
public:
	static uint8BYTE PROTOCOL[2];
	static uint8BYTE ivZ16[16];
	// Empty values for deserialization validation and error messages
	const uint16_t DS_EMPTY_uint16_t;
	const uint32_t DS_EMPTY_uint32_t;
	static uint8BYTE DS_EMPTY_NONCE[16];
	static uint8BYTE DS_EMPTY_BA2[2];
	static uint8BYTE DS_EMPTY_BA3[3];
	static uint8BYTE DS_EMPTY_BA4[4];
	static uint8BYTE DS_EMPTY_BA16[16];
	static uint8BYTE DS_EMPTY_BA12[12];
	static uint8BYTE DS_EMPTY_BA32[32];
	static uint8BYTE DS_EMPTY_BA64[64];
	static uint8BYTE DS_EMPTY_PIB_BA[101];
	static uint8BYTE DS_EMPTY_BA360[360];

	MsgInitValues();
	uint16_t getDS_EMPTY_uint16_t();
	uint32_t getDS_EMPTY_uint32_t();
};

//finds the secret message status whether available or not
class SecretMsgStatus{
public:
	uint16_t available;
	SecretMsgStatus();
	uint16_t getAvailable();
	void setAvailable(uint16_t);
};

/*Request Header structure used for all request messages
of the sigma protocol
*/
class ReqMsgHeader{
public:
	uint8BYTE protocolVer[2];  //2 Bytes
	uint8BYTE resrvd[2]; //2 Bytes
	uint8BYTE reqType[4];  //4 Bytes
	uint8BYTE msgLength[4]; //4 Bytes
	uint8BYTE nonce[16];  //16 Bytes
	//28 Bytes Total

	ReqMsgHeader();

	uint8BYTE *getProtocolVer();
	void setProtocolVer(uint8BYTE[2]);
	uint8BYTE *getResrvd();
	uint8BYTE *getReqType();
	void setReqType(uint8BYTE[4]);
	uint8BYTE *getMsgLength();
	void setMsgLength(uint8BYTE[4]);
	uint8BYTE* getNonce();
	void setNonce(uint8BYTE[16]);
	ReqMsgHeader& equalsTo(ReqMsgHeader &);
};

/*
A utility class with functions that support necessary required conversions
*/
class Converter{
public:
	std::string Converter::byteArrayToHexString(uint8BYTE *, size_t);
	std::string Converter::uint32ToLEString(uint32_t *, size_t);
	uint8BYTE* Converter::uint32ToByteArray(uint32_t);
	uint8BYTE* Converter::uintToByteArray(unsigned int value);
	int Converter::char2int(char input);
	int Converter::byteArrayToInt(uint8BYTE *);
};

// Request message structure for all the request messages to the server
class RequestMessage{
public:
	ReqMsgHeader reqHeader;
	RequestMessage();
	ReqMsgHeader getReqHeader();
	void setReqHeader(ReqMsgHeader);
};

//Provisioning request message structure to the ISV server
class ProvRequestMessage : public RequestMessage{
public:
	ProvRequestMessage(void);
	ProvRequestMessage(std::string);
	std::string GetMsgString();
};

// M0 request body structure to ISV server
class ReqMsg0Body{
public:
	uint8BYTE ExtGID[4];

	ReqMsg0Body();
	uint8BYTE *getExtGID();
	void setExtGID(uint8BYTE[4]);
};

class M0RequestMessage : public RequestMessage{
public:

	ReqMsg0Body reqMsg0Body;
	M0RequestMessage();
	M0RequestMessage(std::string);
	std::string GetMsgString();
	ReqMsg0Body getReqMsg0Body();
	void setReqMsg0Body(ReqMsg0Body);
	//std::string getReqMsg0BodyString();
};

/*
M1 Request body structure
*/
class ReqMsg1Body{
public:
	uint8BYTE gaX[32]; //32 bytes
	uint8BYTE gaY[32];  //32 bytes
	uint8BYTE pltfrmGid[4]; //4 bytes

	ReqMsg1Body();
	uint8BYTE * getGaX();
	void setGaX(uint8BYTE[32]);
	uint8BYTE * getGaY();
	void setGaY(uint8BYTE[32]);
	uint8BYTE * getPltfrmGid();
	void setPltfrmGid(uint8BYTE[4]);
};

class M1RequestMessage : public RequestMessage{
public:
	ReqMsg1Body reqM1Body;

	M1RequestMessage();
	M1RequestMessage(std::string);
	std::string GetMsgString();
	ReqMsg1Body getReqM1Body();
	void setReqM1Body(ReqMsg1Body);
	std::string getReqMsg1BodyString();
};

/*
M3 request body structure
*/
class ReqMsg3Body{
public:
	uint8BYTE aesCmac[16];
	uint8BYTE gaX[32];
	uint8BYTE gaY[32];
	uint8BYTE secProperty[256];
	uint8BYTE quote[RaDefaultQuoteLength];

	ReqMsg3Body();
	uint8BYTE * getAesCmac();
	void setAesCmac(uint8BYTE AesCmac[16]);
	uint8BYTE * getGaX();
	void setGaX(uint8BYTE[32]);
	uint8BYTE * getGaY();
	void setGaY(uint8BYTE[32]);
	uint8BYTE * getSecProperty();
	void setSecProperty(uint8BYTE SecProperty[256]);
	uint8BYTE * getQuote();
	void setQuote(uint8BYTE Quote[RaDefaultQuoteLength]);
};

//M3 request structure
class M3RequestMessage : public RequestMessage{
public:
	ReqMsg3Body reqM3Body;
	ReqMsg3Body getReqM3Body();
	void setReqM3Body(ReqMsg3Body);
	M3RequestMessage();
	M3RequestMessage(std::string);
	std::string GetMsgString();
};

// SGX defined M3 structure
class SGXM3{
public:
	sgx_mac_t                mac;         /* mac_smk(g_a||ps_sec_prop||quote) */
	sgx_ec256_public_t       g_a;         /* the Endian-ness of Ga is Little-Endian */
	sgx_ps_sec_prop_desc_t   ps_sec_prop;
	uint8_t                  quote[RaDefaultQuoteLength];
};

// Header class of all response messages
class ResponseMsgHeader{
public:
	uint8BYTE protocolVer[2];
	uint8BYTE reserved[2];
	uint8BYTE respStatus[4];
	uint8BYTE respType[4];
	uint8BYTE msgLength[4];
	uint8BYTE sessionNonce[16];

	ResponseMsgHeader();
	uint8BYTE *getProtocolVer();
	void setProtocolVer(uint8BYTE[2]);
	uint8BYTE *getReserved();
	uint8BYTE *getRespStatus();
	void setRespStatus(uint8BYTE[4]);
	uint8BYTE *getRespType();
	void setRespType(uint8BYTE[4]);
	uint8BYTE *getMsgLength();
	void setMsgLength(uint8BYTE[4]);
	uint8BYTE* getSessionNonce();
	void setSessionNonce(uint8BYTE[16]);
	ResponseMsgHeader& equalsTo(ResponseMsgHeader &);
};

//Response Message structure 
class ResponseMessage{
public:
	ResponseMessage();
	ResponseMsgHeader respHeader;
	ResponseMsgHeader getRespHeader();
	void setRespHeader(ResponseMsgHeader);
};

//challenge response body structure
class ResponseChallengeMsgBody{
public:
	uint8BYTE reserved[16];

	ResponseChallengeMsgBody();
	uint8BYTE* getReserved();
};

//Challenge response structure
class ChallengeResponse : public ResponseMessage{
public:
	ResponseChallengeMsgBody cRespBody;

	ChallengeResponse();
	ChallengeResponse(std::string);
	ResponseChallengeMsgBody getCRespBody();
	void setCRespBody(ResponseChallengeMsgBody);
	std::string GetMsgString();
};

//M0 Response structure
class M0ResponseMessage : public ResponseMessage{
public:

	M0ResponseMessage();
	M0ResponseMessage(std::string);
	std::string GetMsgString();
};

//M2 response  structure
class ResponseM2Body{
public:
	uint8BYTE gbX[32];
	uint8BYTE gbY[32];
	uint8BYTE spId[16];
	uint8BYTE sigLinkType[2];
	uint8BYTE kdfId[2];
	uint8BYTE sigSpX[32];
	uint8BYTE sigSpY[32];
	uint8BYTE cmacsmk[16];
	uint8BYTE sigrlSize[4];
	uint8BYTE sigRl[32];

	ResponseM2Body();
	uint8BYTE* getGbX();
	void setGbX(uint8BYTE[32]);
	uint8BYTE * getGbY();
	void  setGbY(uint8BYTE[32]);
	uint8BYTE *  getSpId();
	void setSpId(uint8BYTE[16]);
	uint8BYTE* getSigLinkType();
	void setSigLinkType(uint8BYTE[2]);
	uint8BYTE *getKdfId();
	void setKdfId(uint8BYTE[2]);
	uint8BYTE* getSigSpX();
	void setSigSpX(uint8BYTE[32]);
	uint8BYTE* getSigSpY();
	void setSigSpY(uint8BYTE[32]);
	uint8BYTE* getCmacsmk();
	void setCmacsmk(uint8BYTE[16]);
	uint8BYTE* getSigrlSize();
	void setSigrlSize(uint8BYTE[4]);
	uint8BYTE * getSigRl();
	void setSigRl(uint8BYTE[32]);
};
//M2 response structure
class M2ResponseMessage : public ResponseMessage{
public:
	ResponseM2Body respMsg2Body;

	M2ResponseMessage();
	M2ResponseMessage(std::string);
	ResponseM2Body getRespMsg2Body();
	void setRespMsg2Body(ResponseM2Body);
	std::string GetMsgString();

};
//SGX defined M2 structure
class SGXM2ResponseMessage{
public:
	sgx_ec256_public_t       g_b;         /* the Endian-ness of Gb is Little-Endian */
	sgx_spid_t               spid;
	sgx_quote_sign_type_t    quote_type;  /* linkable or unlinkable Quote */
	sgx_ec256_signature_t    sign_gb_ga;  /* In little endian */
	sgx_mac_t                mac;         /* mac_smk(g_b||spid||quote_type||sign_gb_ga) */
	uint32_t                 sig_rl_size;
	uint8_t sig_rl[32];
	std::string GetSGXMsg2String(sgx_ra_msg2_t);
};
//M4 Response body structure
class ResponseM4Body{
public:
	uint8BYTE platformInfo[101];
	uint8BYTE pltfrmInfoRsrvd[3];
	uint8BYTE attestationStatus[4];
	uint8BYTE cmacStatus[16];
	uint8BYTE isvCryptPayloadSize[4];
	uint8BYTE isvClearPayloadSize[4];
	uint8BYTE CryptIv[12];
	uint8BYTE isvPayloadTag[16];
	uint8BYTE isvPayload[360];

	ResponseM4Body();
	uint8BYTE *getPlatformInfo();
	void setPlatformInfo(uint8BYTE[101]);
	uint8BYTE *getPltfrmInfoRsrvd();
	uint8BYTE* getAttestationStatus();
	void setAttestationStatus(uint8BYTE[16]);
	uint8BYTE* getCmacstatus();
	void setCmacstatus(uint8BYTE[16]);
	uint8BYTE* getIsvCryptPayloadSize();
	void setIsvCryptPayloadSize(uint8BYTE[4]);
	uint8BYTE* getIsvClearPayloadSize();
	void setIsvClearPayloadSize(uint8BYTE[4]);
	uint8BYTE *getCryptIv();
	void setCryptIv(uint8BYTE[12]);
	uint8BYTE *getIsvPayloadTag();
	void setIsvPayloadTag(uint8BYTE[16]);
	uint8BYTE *getIsvPayload();
	void setIsvPayload(uint8BYTE[12000]);
	void getIsvKey(uint8BYTE*);
	void getIsvCert(uint8BYTE *);
};

//M4 response structure
class M4ResponseMessage : public ResponseMessage{
public:
	ResponseM4Body respMsg4Body;
	ResponseM4Body getRespMsg4Body();
	void setRespMsg4Body(ResponseM4Body RespMsg4Body);
	M4ResponseMessage();
	M4ResponseMessage(std::string respond);
	std::string GetMsgString();
};
#endif