//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.
/**********************************************************************************
FILENAME:      RaMessages.cpp
DESCRIPTION:   RaMessages.h is the header file. This contains all the message definitions, 
               constants, utility functions to convert from one type of data to other type,
			   and subroutines to print the messages on the console
************************************************************************************/
#include "stdafx.h"
#include "RaMessages.h"
using namespace std;

/*Is used to stop the process because of errors in the
flow of attestation or at the end of the process
@param Input : A char from the keyboard by the user
@output: exiting from the attestaion process
*/
void AbortProcess(){
	//Destroy the enclave before exiting
	std::string buf;
	//DestroyEnclave();
	cout << endl << "  Press Enter to EXIT " << endl;
	while (1){
		getline(cin, buf);
		break;
	}
	exit(0);
}

//initializing the fields with default values
/* To set all request and response message header constructor's Protocol field */
uint8BYTE MsgInitValues::PROTOCOL[2] = { 0x02, 0x00 };

/* To set all request and response message header constructor's nonce and sessionNonce's fields */
uint8BYTE MsgInitValues::ivZ16[16] = { 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/*To set M4 response message constructor's sessionNonce field */
uint8BYTE MsgInitValues::DS_EMPTY_NONCE[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/*to set all request and response message header constructor's Protocol field  */
uint8BYTE MsgInitValues::DS_EMPTY_BA2[2] = { 0xFF, 0xFF };

/* to set the pltfrmInfoRsrvd field of M4 */
uint8BYTE MsgInitValues::DS_EMPTY_BA3[3] = { 0xFF, 0xFF, 0xFF };

/*To set the M2 response body sigrlSize and sigLinkType, M4 response body's isvCryptPayloadSize constructor's fields to empty values*/
uint8BYTE MsgInitValues::DS_EMPTY_BA4[4] = { 0xFF, 0xFF, 0xFF, 0xFF };

/* To set the M4 response bosy cryptIV field */
uint8BYTE MsgInitValues::DS_EMPTY_BA12[12] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* To set Request message header's nonce;M2 Response body constructor's spId, cmacsmk; M3 request body constructor's aesCmac;
M4 response body's attestationStatus, cmacStatus, CryptIv, isvPayloadTag fields to 16 byte empty values*/
uint8BYTE MsgInitValues::DS_EMPTY_BA16[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* To set M1 request body  Tconstructor's gaX,gaY, pltfrmGid; M3 request body constructor's gaX,gaY;
M2 response body constructor's gbX, gbY,sigSpX,sigSpY fieldso empty 32 bytes*/
uint8BYTE MsgInitValues::DS_EMPTY_BA32[32] = { 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF };

/*To set M3 request body constructor's secProperty, quote;
M4 response body's isvPayload fields to 64 bytes of empty values */
uint8BYTE MsgInitValues::DS_EMPTY_BA64[64] = { 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

uint8BYTE MsgInitValues::DS_EMPTY_BA360[360] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/*To set M4 response body constructor's pltfrmInfo field to 101 bytes of empty values*/
uint8BYTE MsgInitValues::DS_EMPTY_PIB_BA[101] = { 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF };

/* MsgInitValues  constructor , constants initialized to empty values*/
MsgInitValues::MsgInitValues(void) :DS_EMPTY_uint16_t(0XFFF), DS_EMPTY_uint32_t(0xFFFFFFFF){	}

/*Checks whether secret is available with enclave or not. returns the availability status in 16 bits unsigned int*/
SecretMsgStatus::SecretMsgStatus(){}
uint16_t SecretMsgStatus::getAvailable(){ return available; }
void SecretMsgStatus::setAvailable(uint16_t Available) {
	available = Available;
}

/*Utility function that converts a byte array to hexa decimal number, and then to a string
@param value[] is a byte array
@param size tells the size of the array to be converted
@returns result which is a hexa decimal representation of the byte array in string format
*/
std::string Converter::byteArrayToHexString(uint8BYTE value[], size_t size){
	std::string result;

	if (size >  0){
		for (int i = 0; i <= (int)size - 1; i++){
			std::ostringstream oss;
			uint16_t uValue = value[i];
			oss << std::hex << uValue;
			result += oss.str();
		}
	}
	else{
		cout << "Incorrect size parameter to byteArrayToHexString method" << endl;
		AbortProcess();
	}
	return result;
}

int Converter::char2int(char input){
	if (input >= '0' && input <= '9')
		return input - '0';
	if (input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	if (input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	throw std::invalid_argument("Invalid input string");
}

/* converts a 32 bit unsigned number to uint8[4] array**/
uint8BYTE* Converter::uint32ToByteArray(uint32_t value){
	static uint8BYTE result[4];
	result[0] = value;
	result[1] = value >> 8;
	result[2] = value >> 16;
	result[3] = value >> 24;
	return result;
}

/* converts an integer value to a byte array*/
uint8BYTE* Converter::uintToByteArray(unsigned int value){
	static uint8BYTE result[4];
	result[0] = value;
	result[1] = value >> 8;
	result[2] = value >> 16;
	return result;
}

/* converts a byte array to an integer value*/
int Converter::byteArrayToInt(uint8BYTE *value){
	int result;
	result = value[3] << 24 | value[2] << 16 | value[1] << 8 | value[0];
	return result;
}

/*
Converts an uint32 array to little endian format by swapping the bytes and
then converts to a string
@param value is an uint32 array input
@parm size is the size of the input array
@returns a string object, result
*/
std::string Converter::uint32ToLEString(uint32_t value[], size_t size){
	std::string result;
	if (size > 0){
		for (int i = 0; i <= (int)size - 1; i++){
			std::ostringstream oss;
			uint32_t lEndian;
			lEndian = _byteswap_ulong(value[i]);
			oss << std::setw(8) << std::setfill('0') << std::right << std::hex << lEndian;
			result += oss.str();
		}
	}
	else{
		cout << "Invalid size parameter to uint32ToLEString method" << endl;
		AbortProcess();
	}
	return result;
}

//Default constructor for all the request message headers
ReqMsgHeader::ReqMsgHeader(){
	Converter converter;
	uint8BYTE temp[2] = { 0x00, 0x00 };
	std::memcpy(resrvd, temp, 2);
	std::memcpy(protocolVer, MsgInitValues::DS_EMPTY_BA2, 2);
	uint8_t *p = converter.uint32ToByteArray(enMsgType::RaReserved);
	std::memcpy(reqType, p, 4);
	std::memcpy(msgLength, (converter.uint32ToByteArray(enMsgType::RaReserved)), 4);
	std::memcpy(nonce, MsgInitValues::DS_EMPTY_BA16, 16);
}

//getters and setters for each field
uint8BYTE *ReqMsgHeader::getProtocolVer() { return protocolVer; }
void ReqMsgHeader::setProtocolVer(uint8BYTE ProtocolVer[2]){ std::memcpy(protocolVer, ProtocolVer, 2); }
uint8BYTE* ReqMsgHeader::getResrvd() { return resrvd; }
uint8BYTE *ReqMsgHeader::getReqType(){ return reqType; }
void ReqMsgHeader::setReqType(uint8BYTE ReqType[]){ memcpy(reqType, ReqType, 4); }
uint8BYTE *ReqMsgHeader::getMsgLength(){ return msgLength; }
void ReqMsgHeader::setMsgLength(uint8BYTE MsgLength[]){ memcpy(msgLength, MsgLength, 4); }
uint8BYTE* ReqMsgHeader::getNonce(){ return nonce; }
void ReqMsgHeader::setNonce(uint8BYTE Nonce[]){ memcpy(nonce, Nonce, 16); }
RequestMessage::RequestMessage() { setReqHeader(ReqMsgHeader()); }
ReqMsgHeader RequestMessage::getReqHeader() { return  ReqMsgHeader(); }
void RequestMessage::setReqHeader(ReqMsgHeader reqMsgHeader) { reqHeader = reqMsgHeader; }
ReqMsgHeader& ReqMsgHeader::equalsTo(ReqMsgHeader &a){
	this->setProtocolVer(a.getProtocolVer());
	this->setReqType(a.getReqType());
	this->setMsgLength(a.getMsgLength());
	this->setNonce(a.getNonce());
	return *this;
}

//Provrequest message default constructor to populate an "empty" object with values that allow 
//dection of missing fields after deserialization
ProvRequestMessage::ProvRequestMessage(void){
	Converter converter;
	std::memcpy(reqHeader.protocolVer, MsgInitValues::DS_EMPTY_BA2, 2);
	uint8BYTE *t = converter.uint32ToByteArray((uint32_t)enMsgType::RaReserved);
	std::memcpy(reqHeader.reqType, t, 4);
	uint8_t *p = converter.uint32ToByteArray(enDefaultLength::RaDefaultEmptyLength);
	std::memcpy(reqHeader.msgLength, p, 4);
	std::memcpy(reqHeader.nonce, MsgInitValues::DS_EMPTY_BA16, 16);
}

//Constructor for an actual request message
//for use as a reference or for making a real request.
ProvRequestMessage::ProvRequestMessage(string request){
	if (request != ""){
		Converter converter;
		std::memcpy(reqHeader.protocolVer, MsgInitValues::PROTOCOL, 2);
		std::memcpy(reqHeader.reqType, converter.uint32ToByteArray(enMsgType::RaProvisionReq), 4);
		uint8_t *p = converter.uint32ToByteArray(enDefaultLength::RaDefaultPreqLength);
		std::memcpy(reqHeader.msgLength, p, 4);
		srand((unsigned int)time(NULL));
		for (int i = 0; i <16; i++){
			reqHeader.nonce[i] = rand() % 256;
		}
	}
	else{
		cout << "Bad parameter to ProvRequestMessage constructor" << endl;
		AbortProcess();
	}
}

/*Function that prints all the fields of the message in a
hexa decimal string format to the console*/
std::string ProvRequestMessage::GetMsgString(){
	string provstr = "";
	Converter converter;
	provstr = converter.byteArrayToHexString(reqHeader.getProtocolVer(), 2);
	provstr += converter.byteArrayToHexString(reqHeader.getResrvd(), 2);
	provstr += converter.byteArrayToHexString(reqHeader.getReqType(), 4);
	provstr += converter.byteArrayToHexString(reqHeader.getMsgLength(), 4);
	if (reqHeader.getNonce() != NULL)
		provstr += converter.byteArrayToHexString(reqHeader.getNonce(), 16);
	return provstr;
}
ReqMsg0Body::ReqMsg0Body(){
	std::memcpy(ExtGID, MsgInitValues::DS_EMPTY_BA4, 4);
}

ReqMsg0Body M0RequestMessage::getReqMsg0Body(){ return ReqMsg0Body(); }
void M0RequestMessage::setReqMsg0Body(ReqMsg0Body ReqMsg0Body) { reqMsg0Body = ReqMsg0Body; }

//Getters and setters of M0 request
uint8BYTE * ReqMsg0Body::getExtGID(){ return ExtGID; }
void ReqMsg0Body::setExtGID(uint8BYTE extGID[]){ std::memcpy(ExtGID, extGID, 4); }

M0RequestMessage::M0RequestMessage(void){
	Converter converter;
	std::memcpy(reqHeader.protocolVer, MsgInitValues::DS_EMPTY_BA2, 2);
	uint8BYTE *t = converter.uint32ToByteArray((uint32_t)enMsgType::RaReserved);
	std::memcpy(reqHeader.reqType, t, 4);
	uint8_t *p = converter.uint32ToByteArray(enDefaultLength::RaDefaultEmptyLength);
	std::memcpy(reqHeader.msgLength, p, 4);
	std::memcpy(reqHeader.nonce, MsgInitValues::DS_EMPTY_BA16, 16);
}

M0RequestMessage::M0RequestMessage(string request){
	if (request != ""){
		Converter converter;
		std::memcpy(reqHeader.protocolVer, MsgInitValues::PROTOCOL, 2);
		std::memcpy(reqHeader.reqType, converter.uint32ToByteArray(enMsgType::RaMessage0Req), 4);
		uint8_t *p = converter.uint32ToByteArray(enDefaultLength::RaDefaultM0ReqLength);
		std::memcpy(reqHeader.msgLength, p, 4);
		std::memcpy(reqHeader.nonce, MsgInitValues::DS_EMPTY_BA16, 16);
	}
	else{
		cout << "Bad parameter to M0RequestMessage constructor" << endl;
		AbortProcess();
	}
}

/*Function that prints all the fields of the message in a
hexa decimal string format to the console*/
std::string M0RequestMessage::GetMsgString(){
	string m0str = "";
	Converter converter;
	m0str = converter.byteArrayToHexString(reqHeader.getProtocolVer(), 2);
	m0str += converter.byteArrayToHexString(reqHeader.getResrvd(), 2);
	m0str += converter.byteArrayToHexString(reqHeader.getReqType(), 4);
	m0str += converter.byteArrayToHexString(reqHeader.getMsgLength(), 4);
	if (reqHeader.getNonce() != NULL)
		m0str += converter.byteArrayToHexString(reqHeader.getNonce(), 16);
	m0str += converter.byteArrayToHexString(reqMsg0Body.getExtGID(), 4);
	return m0str;
}

//M1 body default constructor to populate an "empty" object with values that allow 
//dection of missing fields after deserialization
ReqMsg1Body::ReqMsg1Body(){
	std::memcpy(gaX, MsgInitValues::DS_EMPTY_BA32, 32);
	std::memcpy(gaY, MsgInitValues::DS_EMPTY_BA32, 32);
	std::memcpy(pltfrmGid, MsgInitValues::DS_EMPTY_BA32, 4);
}

//Getters and setters of M1 request
uint8BYTE * ReqMsg1Body::getGaX(){ return gaX; }
void ReqMsg1Body::setGaX(uint8BYTE GaX[]){ std::memcpy(gaX, GaX, 32); }
uint8BYTE * ReqMsg1Body::getGaY() { return gaY; }
void ReqMsg1Body::setGaY(uint8BYTE GaY[32]){ std::memcpy(gaY, GaY, 32); }
uint8BYTE * ReqMsg1Body::getPltfrmGid() { return pltfrmGid; }
void ReqMsg1Body::setPltfrmGid(uint8BYTE PltfrmGid[4]) { std::memcpy(pltfrmGid, PltfrmGid, 4); }
ReqMsg1Body M1RequestMessage::getReqM1Body(){ return ReqMsg1Body(); }
void M1RequestMessage::setReqM1Body(ReqMsg1Body ReqMsg1Body) { reqM1Body = ReqMsg1Body; }

//M1 request Constructor to populate an "empty" object with values that allow 
//detection of missing fields after deserialization.
M1RequestMessage::M1RequestMessage(){
	Converter converter;
	std::memcpy(reqHeader.protocolVer, MsgInitValues::DS_EMPTY_BA2, 2);
	uint8_t *p = converter.uint32ToByteArray((uint32_t)enMsgType::RaReserved);
	std::memcpy(reqHeader.reqType, p, 4);
	std::memcpy(reqHeader.msgLength, converter.uint32ToByteArray((uint32_t)enDefaultLength::RaDefaultEmptyLength), 4);
	std::memcpy(reqHeader.nonce, MsgInitValues::ivZ16, 16);
	reqM1Body = ReqMsg1Body();
}

//M1 request Constructor for an actual request message
//for use as a reference or for making a real request.
M1RequestMessage::M1RequestMessage(string request) {
	if (request != ""){
		Converter converter;
		std::memcpy(reqHeader.protocolVer, MsgInitValues::PROTOCOL, 2);
		uint8_t *p = converter.uint32ToByteArray((uint32_t)enMsgType::RaMessage1Req);
		std::memcpy(reqHeader.reqType, p, 4);
		std::memcpy(reqHeader.msgLength, converter.uint32ToByteArray((uint32_t)enDefaultLength::RaDefaultM1Length), 4);
		std::memcpy(reqHeader.nonce, MsgInitValues::ivZ16, 16);
		reqM1Body = ReqMsg1Body();
	}
	else{
		cout << "Bad parameter to M1RequestMessage constructor" << endl;
		AbortProcess();
	}
}

/*Function that prints all the fields of the M1 request in a hexa decimal string format
@returns string representation of the M1 request to the console
*/
std::string M1RequestMessage::GetMsgString() {
	string m1str = "";
	Converter converter;
	m1str = converter.byteArrayToHexString(reqHeader.getProtocolVer(), 2);
	m1str += converter.byteArrayToHexString(reqHeader.getResrvd(), 2);
	m1str += converter.byteArrayToHexString(reqHeader.getReqType(), 4);
	m1str += converter.byteArrayToHexString(reqHeader.getMsgLength(), 4);
	if (reqHeader.nonce != NULL)
		m1str += converter.byteArrayToHexString(reqHeader.getNonce(), 16);
	if (reqM1Body.gaX != NULL && reqM1Body.gaY != NULL){
		m1str += converter.byteArrayToHexString(reqM1Body.getGaX(), 32);
		m1str += converter.byteArrayToHexString(reqM1Body.getGaY(), 32);
	}
	m1str += converter.byteArrayToHexString(reqM1Body.getPltfrmGid(), 4);
	return m1str;
}

/*Utility function to print the M1 request body in hexa decimal string format*/
std::string M1RequestMessage::getReqMsg1BodyString() {
	string m1BodyStr = "";
	Converter converter;
	if (this->getReqM1Body().gaX != NULL && this->getReqM1Body().gaY != NULL){
		m1BodyStr += converter.byteArrayToHexString(reqM1Body.getGaX(), 32);
		m1BodyStr += converter.byteArrayToHexString(reqM1Body.getGaY(), 32);
	}
	m1BodyStr += converter.byteArrayToHexString(reqM1Body.getPltfrmGid(), 4);
	return m1BodyStr;
}

/* M3 request body default constructor to to populate an "empty" object with values that allow
dection of missing fields after deserialization. */
ReqMsg3Body::ReqMsg3Body(){
	std::memcpy(aesCmac, MsgInitValues::DS_EMPTY_BA16, 16);
	std::memcpy(gaX, MsgInitValues::DS_EMPTY_BA32, 32);
	std::memcpy(gaY, MsgInitValues::DS_EMPTY_BA32, 32);
	std::memcpy(secProperty, MsgInitValues::DS_EMPTY_BA64, 64);
	std::memcpy(quote, MsgInitValues::DS_EMPTY_BA64, 64);
}

//getters and setters for M3 request body fields
uint8BYTE * ReqMsg3Body::getAesCmac(){ return aesCmac; }
void ReqMsg3Body::setAesCmac(uint8BYTE AesCmac[16]) { std::memcpy(aesCmac, AesCmac, 16); }
uint8BYTE * ReqMsg3Body::getGaX() { return gaX; }
void ReqMsg3Body::setGaX(uint8BYTE GaX[32]) { std::memcpy(gaX, GaX, 32); }
uint8BYTE * ReqMsg3Body::getGaY() { return gaY; }
void ReqMsg3Body::setGaY(uint8BYTE GaY[32]) { std::memcpy(gaY, GaY, 32); }
uint8BYTE * ReqMsg3Body::getSecProperty() { return secProperty; }
void ReqMsg3Body::setSecProperty(uint8BYTE SecProperty[256]) { std::memcpy(secProperty, SecProperty, 256); }
uint8BYTE * ReqMsg3Body::getQuote() { return quote; }
void ReqMsg3Body::setQuote(uint8BYTE Quote[enDefaultLength::RaDefaultQuoteLength]) { std::memcpy(quote, Quote, enDefaultLength::RaDefaultQuoteLength); }

ReqMsg3Body M3RequestMessage::getReqM3Body() { return ReqMsg3Body(); }
void M3RequestMessage::setReqM3Body(ReqMsg3Body ReqM3Body) { reqM3Body = ReqM3Body; }

//M3 request default constructor to populate an "empty" object with values that allow 
//detection of missing fields after deserialization.
M3RequestMessage::M3RequestMessage(){
	Converter converter;
	std::memcpy(reqHeader.protocolVer, MsgInitValues::DS_EMPTY_BA2, 2);
	uint8_t *p = converter.uint32ToByteArray(enMsgType::RaReserved);
	std::memcpy(reqHeader.reqType, p, 4);
	std::memcpy(reqHeader.msgLength, converter.uint32ToByteArray(enDefaultLength::RaDefaultEmptyLength), 4);
	std::memcpy(reqHeader.nonce, MsgInitValues::ivZ16, 16);
	reqM3Body = ReqMsg3Body();
}

//M3 Request Constructor for an actual request message
//for use as a reference or for making a real request.
M3RequestMessage::M3RequestMessage(std::string request){
	if (request != ""){
		Converter converter;
		std::memcpy(reqHeader.protocolVer, MsgInitValues::PROTOCOL, 2);
		uint8_t *p = converter.uint32ToByteArray(enMsgType::RaMessage3Req);
		std::memcpy(reqHeader.reqType, p, 4);
		std::memcpy(reqHeader.msgLength, converter.uint32ToByteArray(enDefaultLength::RaDefaultM3Length), 4);
		std::memcpy(reqHeader.nonce, MsgInitValues::ivZ16, 16);
		reqM3Body = ReqMsg3Body();
	}
	else{
		cout << "Bad parameter to M3RequestMessage constructor" << endl;
		AbortProcess();
	}
}

//Function that prints all the fields of the M3 in a hexa decimal string format
std::string M3RequestMessage::GetMsgString() {
	string m3str = "";
	Converter converter;
	m3str = converter.byteArrayToHexString(reqHeader.getProtocolVer(), 2) + "\n";
	m3str += converter.byteArrayToHexString(reqHeader.getResrvd(), 2) + "\n";
	m3str += converter.byteArrayToHexString(reqHeader.getReqType(), 4) + "\n";
	m3str += converter.byteArrayToHexString(reqHeader.getMsgLength(), 4) + "\n";
	if (reqHeader.getNonce() != NULL && reqM3Body.getAesCmac() != NULL
		&& reqM3Body.getGaX() != NULL && reqM3Body.getGaY() != NULL
		&& reqM3Body.getQuote() != NULL&&reqM3Body.getSecProperty() != NULL){
		m3str += converter.byteArrayToHexString(reqHeader.getNonce(), 16) + "\n";
		m3str += converter.byteArrayToHexString(reqM3Body.getAesCmac(), 16) + "\n";
		m3str += converter.byteArrayToHexString(reqM3Body.getGaX(), 32) + "\n";
		m3str += converter.byteArrayToHexString(reqM3Body.getGaY(), 32) + "\n";
		m3str += converter.byteArrayToHexString(reqM3Body.getSecProperty(), 256) + "\n";
		m3str += converter.byteArrayToHexString(reqM3Body.getQuote(), enDefaultLength::RaDefaultQuoteLength);
	}
	return m3str;
}

//default constructor for response message header
ResponseMsgHeader::ResponseMsgHeader(){
	uint8BYTE temp[2] = { 0x00, 0x00 };
	memcpy(reserved, temp, 2);
}

//getters and setters for response message headers
uint8BYTE* ResponseMsgHeader::getProtocolVer(){ return protocolVer; }
void ResponseMsgHeader::setProtocolVer(uint8BYTE ProtocolVer[2]){ std::memcpy(protocolVer, ProtocolVer, 2); }
uint8BYTE* ResponseMsgHeader::getReserved(){ return reserved; }
uint8BYTE* ResponseMsgHeader::getRespStatus(){ return respStatus; }
void ResponseMsgHeader::setRespStatus(uint8BYTE RespStatus[4]){ std::memcpy(respStatus, RespStatus, 4); }
uint8BYTE* ResponseMsgHeader::getRespType(){ return respType; }
void ResponseMsgHeader::setRespType(uint8BYTE RespType[4]){ std::memcpy(respType, RespType, 4); }
uint8BYTE* ResponseMsgHeader::getMsgLength(){ return msgLength; }
void ResponseMsgHeader::setMsgLength(uint8BYTE MsgLength[4]){ std::memcpy(msgLength, MsgLength, 4); }
uint8BYTE* ResponseMsgHeader::getSessionNonce(){ return sessionNonce; }
void ResponseMsgHeader::setSessionNonce(uint8BYTE SessionNonce[]){ std::memcpy(sessionNonce, SessionNonce, 16); }
ResponseMessage::ResponseMessage(){ setRespHeader(ResponseMsgHeader()); }
ResponseMsgHeader ResponseMessage::getRespHeader() { return  ResponseMsgHeader(); }
void ResponseMessage::setRespHeader(ResponseMsgHeader RespMsgHeader) { respHeader = RespMsgHeader; }
ResponseMsgHeader& ResponseMsgHeader::equalsTo(ResponseMsgHeader& a){
	setProtocolVer(a.getProtocolVer());
	setRespStatus(a.getRespStatus());
	setRespType(a.getRespType());
	setMsgLength(a.getMsgLength());
	setSessionNonce(a.getSessionNonce());
	return *this;
}

ResponseChallengeMsgBody::ResponseChallengeMsgBody(){ std::memcpy(reserved, MsgInitValues::ivZ16, 16); }
uint8BYTE* ResponseChallengeMsgBody::getReserved() { return reserved; }
void ChallengeResponse::setCRespBody(ResponseChallengeMsgBody CRespBody){ cRespBody = CRespBody; }
ResponseChallengeMsgBody ChallengeResponse::getCRespBody(){ return ResponseChallengeMsgBody(); }

/*Challenge reponse default constructor with empty values to detect the missing field values
after the deserialization*/
ChallengeResponse::ChallengeResponse(){
	Converter converter;
	std::memcpy(respHeader.protocolVer, MsgInitValues::DS_EMPTY_BA2, 2);
	uint8_t *p = converter.uint32ToByteArray(enStatusCodes::RaErrUnknown);
	std::memcpy(respHeader.respStatus, p, 4);
	std::memcpy(respHeader.respType, converter.uint32ToByteArray(enMsgType::RaReserved), 4);
	std::memcpy(respHeader.msgLength, converter.uint32ToByteArray(enDefaultLength::RaDefaultEmptyLength), 4);
	std::memcpy(respHeader.sessionNonce, MsgInitValues::ivZ16, 16);
	cRespBody = ResponseChallengeMsgBody();
}
//Constructor for an actual response message
//for use as a reference or for making a real response
ChallengeResponse::ChallengeResponse(string respond){
	if (respond != ""){
		Converter converter;
		std::memcpy(respHeader.protocolVer, MsgInitValues::PROTOCOL, 2);
		uint8_t *p = converter.uint32ToByteArray(enStatusCodes::RaErrNone);
		std::memcpy(respHeader.respStatus, p, 4);
		std::memcpy(respHeader.respType, converter.uint32ToByteArray(enMsgType::RaChallengeResp), 4);
		std::memcpy(respHeader.msgLength, converter.uint32ToByteArray(enDefaultLength::RaDefaultCrespLength), 4);
		std::memcpy(respHeader.sessionNonce, MsgInitValues::ivZ16, 16);
		cRespBody = ResponseChallengeMsgBody();
	}
	else{
		cout << "Bad parameter to Challenge response construtor" << endl;
		AbortProcess();
	}
}

/*/Function that prints all the fields of the challenge response message in a hexa decimal string format
@returns a string object
*/
string ChallengeResponse::GetMsgString() {
	string cRespStr = "";
	Converter converter;
	cRespStr = converter.byteArrayToHexString(respHeader.getProtocolVer(), 2) + "\n";
	cRespStr += converter.byteArrayToHexString(respHeader.getReserved(), 2) + "\n";
	cRespStr += converter.byteArrayToHexString(respHeader.getRespStatus(), 4) + "\n";
	cRespStr += converter.byteArrayToHexString(respHeader.getRespType(), 4) + "\n";
	cRespStr += converter.byteArrayToHexString(respHeader.getMsgLength(), 4) + "\n";
	cRespStr += converter.byteArrayToHexString(respHeader.getSessionNonce(), 16) + "\n";
	return cRespStr;
}

/* M0 response default constructor with empty values to populate the missing
field values after deserialization*/
M0ResponseMessage::M0ResponseMessage(){
	Converter converter;
	std::memcpy(respHeader.protocolVer, MsgInitValues::DS_EMPTY_BA2, 2);
	uint8_t *p = converter.uint32ToByteArray(enStatusCodes::RaErrUnknown);
	std::memcpy(respHeader.respStatus, p, 4);
	std::memcpy(respHeader.respType, converter.uint32ToByteArray(enMsgType::RaReserved), 4);
	std::memcpy(respHeader.msgLength, converter.uint32ToByteArray(enDefaultLength::RaDefaultEmptyLength), 4);
	std::memcpy(respHeader.sessionNonce, MsgInitValues::ivZ16, 16);
}

M0ResponseMessage::M0ResponseMessage(std::string respond){
	if (respond != ""){
		Converter converter;
		std::memcpy(respHeader.protocolVer, MsgInitValues::PROTOCOL, 2);
		uint8_t *p = converter.uint32ToByteArray(enStatusCodes::RaErrNone);
		std::memcpy(respHeader.respStatus, p, 4);
		std::memcpy(respHeader.respType, converter.uint32ToByteArray(enMsgType::RaMessage0Resp), 4);
		std::memcpy(respHeader.msgLength, converter.uint32ToByteArray(enDefaultLength::RaDefaultM0RespLength), 4);
		std::memcpy(respHeader.sessionNonce, MsgInitValues::ivZ16, 16);
	}
	else {
		cout << "Bad parameter to M0 response Message construtor" << endl;
		AbortProcess();
	}
}

//Function that prints all the fields of the M0 response in a hexa decimal string format
std::string M0ResponseMessage::GetMsgString(){
	string m0str = "";
	Converter converter;
	m0str = converter.byteArrayToHexString(respHeader.getProtocolVer(), 2) + "\n";
	m0str += converter.byteArrayToHexString(respHeader.getReserved(), 2) + "\n";
	m0str += converter.byteArrayToHexString(respHeader.getRespStatus(), 4) + "\n";
	m0str += converter.byteArrayToHexString(respHeader.getRespType(), 4) + "\n";
	m0str += converter.byteArrayToHexString(respHeader.getMsgLength(), 4) + "\n";
	m0str += converter.byteArrayToHexString(respHeader.getSessionNonce(), 16) + "\n";
	return m0str;
}

/* M2 response body default constructor with empty values to populate the missing
field values after deserialization*/
ResponseM2Body::ResponseM2Body(){
	std::memcpy(gbX, MsgInitValues::DS_EMPTY_BA32, 32);
	std::memcpy(gbY, MsgInitValues::DS_EMPTY_BA32, 32);
	std::memcpy(spId, MsgInitValues::DS_EMPTY_BA16, 16);
	std::memcpy(sigLinkType, MsgInitValues::DS_EMPTY_BA2, 2);
	std::memcpy(kdfId, MsgInitValues::DS_EMPTY_BA2, 2);
	std::memcpy(sigSpX, MsgInitValues::DS_EMPTY_BA32, 32);
	std::memcpy(sigSpY, MsgInitValues::DS_EMPTY_BA32, 32);
	std::memcpy(cmacsmk, MsgInitValues::DS_EMPTY_BA16, 16);
	std::memcpy(sigrlSize, MsgInitValues::DS_EMPTY_BA4, 4);
	uint8BYTE *pointer = NULL;
	pointer = &sigRl[0];
}

//getters and setters for the M2 Response body
uint8BYTE* ResponseM2Body::getGbX(){ return gbX; }
void ResponseM2Body::setGbX(uint8BYTE GbX[32]){ std::memcpy(gbX, GbX, 32); }
uint8BYTE * ResponseM2Body::getGbY() { return gbY; }
void  ResponseM2Body::setGbY(uint8BYTE GbY[32]){ std::memcpy(gbY, GbY, 32); }
uint8BYTE *  ResponseM2Body::getSpId(){ return spId; }
void ResponseM2Body::setSpId(uint8BYTE SpId[16]) { std::memcpy(spId, SpId, 16); }
uint8BYTE* ResponseM2Body::getSigLinkType(){ return sigLinkType; }
void ResponseM2Body::setSigLinkType(uint8BYTE SigLinkType[2]) { std::memcpy(sigLinkType, SigLinkType, 2); }
uint8BYTE* ResponseM2Body::getKdfId(){ return kdfId; }
void ResponseM2Body::setKdfId(uint8BYTE KdfId[2]) { std::memcpy(kdfId, KdfId, 2); }
uint8BYTE* ResponseM2Body::getSigSpX(){ return sigSpX; }
void ResponseM2Body::setSigSpX(uint8BYTE SigSpX[32]){ std::memcpy(sigSpX, SigSpX, 32); }
uint8BYTE* ResponseM2Body::getSigSpY(){ return sigSpY; }
void ResponseM2Body::setSigSpY(uint8BYTE SigSpY[32]){ std::memcpy(sigSpY, SigSpY, 32); }
uint8BYTE* ResponseM2Body::getCmacsmk(){ return cmacsmk; }
void ResponseM2Body::setCmacsmk(uint8BYTE Cmacsmk[16]){ std::memcpy(cmacsmk, Cmacsmk, 16); }
uint8BYTE* ResponseM2Body::getSigrlSize(){ return sigrlSize; }
void ResponseM2Body::setSigrlSize(uint8BYTE SigrlSize[]){ std::memcpy(sigrlSize, SigrlSize, 4); }
uint8BYTE * ResponseM2Body::getSigRl(){ return sigRl; }
void ResponseM2Body::setSigRl(uint8BYTE SigRl[32]){ std::memcpy(sigRl, SigRl, 32); }

//M2 response default constructor 
M2ResponseMessage::M2ResponseMessage(){
	Converter converter;
	std::memcpy(respHeader.protocolVer, MsgInitValues::DS_EMPTY_BA2, 2);
	uint8_t *p = converter.uint32ToByteArray(enStatusCodes::RaErrUnknown);
	std::memcpy(respHeader.respStatus, p, 4);
	std::memcpy(respHeader.respType, converter.uint32ToByteArray(enMsgType::RaReserved), 4);
	std::memcpy(respHeader.msgLength, converter.uint32ToByteArray(enDefaultLength::RaDefaultEmptyLength), 4);
	std::memcpy(respHeader.sessionNonce, MsgInitValues::ivZ16, 16);
	respMsg2Body = ResponseM2Body();
}

//M2 response Constructor for an actual response 
//as a reference or for making a real response
M2ResponseMessage::M2ResponseMessage(std::string respond){
	if (respond != ""){
		Converter converter;
		std::memcpy(respHeader.protocolVer, MsgInitValues::PROTOCOL, 2);
		uint8_t *p = converter.uint32ToByteArray(enStatusCodes::RaErrNone);
		std::memcpy(respHeader.respStatus, p, 4);
		std::memcpy(respHeader.respType, converter.uint32ToByteArray(enMsgType::RaMessage2Resp), 4);
		std::memcpy(respHeader.msgLength, converter.uint32ToByteArray(enDefaultLength::RaDefaultM2Length), 4);
		std::memcpy(respHeader.sessionNonce, MsgInitValues::ivZ16, 16);
		respMsg2Body = ResponseM2Body();
	}
	else {
		cout << "Bad parameter to M2 response Message construtor" << endl;
		AbortProcess();
	}
}

ResponseM2Body M2ResponseMessage::getRespMsg2Body(){ return respMsg2Body; }
void M2ResponseMessage::setRespMsg2Body(ResponseM2Body M2ResponseBody){
	respMsg2Body.setGbX(M2ResponseBody.getGbX());
	respMsg2Body.setGbY(M2ResponseBody.getGbY());
	respMsg2Body.setSpId(M2ResponseBody.getSpId());
	respMsg2Body.setSigLinkType(M2ResponseBody.getSigLinkType());
	respMsg2Body.setKdfId(M2ResponseBody.getKdfId());
	respMsg2Body.setSigSpX(M2ResponseBody.getSigSpX());
	respMsg2Body.setSigSpY(M2ResponseBody.getSigSpY());
	respMsg2Body.setCmacsmk(M2ResponseBody.getCmacsmk());
	respMsg2Body.setSigrlSize(M2ResponseBody.getSigrlSize());
	uint8BYTE nullArray[32] = { 0 };
	uint8BYTE sigRl[32];
	bool isNull = true;
	std::memcpy(sigRl, M2ResponseBody.getSigRl(), 32);
	for (int x = 0; x<32; x++){
		if (sigRl[x] != nullArray[x]){
			isNull = false;
			break;
		}
	}
	if (!isNull){
		respMsg2Body.setSigRl(M2ResponseBody.getSigRl());
	}
	else {
		respMsg2Body.setSigRl(nullArray);
	}
}

//Function that prints all the fields of the M2 response in a hexa decimal string format
std::string M2ResponseMessage::GetMsgString(){
	string m2str = "";
	Converter converter;
	m2str = converter.byteArrayToHexString(respHeader.getProtocolVer(), 2) + "\n";
	m2str += converter.byteArrayToHexString(respHeader.getReserved(), 2) + "\n";
	m2str += converter.byteArrayToHexString(respHeader.getRespStatus(), 4) + "\n";
	m2str += converter.byteArrayToHexString(respHeader.getRespType(), 4) + "\n";
	m2str += converter.byteArrayToHexString(respHeader.getMsgLength(), 4) + "\n";
	m2str += converter.byteArrayToHexString(respHeader.getSessionNonce(), 16) + "\n";
	m2str += converter.byteArrayToHexString(respMsg2Body.getGbX(), 32) + "\n";
	m2str += converter.byteArrayToHexString(this->respMsg2Body.getGbY(), 32) + "\n";
	m2str += converter.byteArrayToHexString(this->respMsg2Body.getSpId(), 16) + "\n";
	m2str += converter.byteArrayToHexString(this->respMsg2Body.getSigLinkType(), 2) + "\n";
	m2str += converter.byteArrayToHexString(this->respMsg2Body.getKdfId(), 2) + "\n";
	m2str += converter.byteArrayToHexString(this->respMsg2Body.getSigSpX(), 32) + "\n";
	m2str += converter.byteArrayToHexString(this->respMsg2Body.getSigSpY(), 32) + "\n";
	m2str += converter.byteArrayToHexString(this->respMsg2Body.getCmacsmk(), 16) + "\n";
	m2str += converter.byteArrayToHexString(this->respMsg2Body.getSigrlSize(), 4) + "\n";
	if (respMsg2Body.getSigRl() != NULL){
		m2str += converter.byteArrayToHexString(this->respMsg2Body.getSigRl(), 32);
	}
	return m2str;
}

//Function that prints all the fields of the SGX message2 response in a hexa decimal string format
std::string SGXM2ResponseMessage::GetSGXMsg2String(sgx_ra_msg2_t smsg2){
	string sgxM2str = "";
	Converter converter;
	uint8_t lType[1] = { 0x00 };
	sgxM2str += converter.byteArrayToHexString(smsg2.g_b.gx, 32) + "\n";
	sgxM2str += converter.byteArrayToHexString(smsg2.g_b.gy, 32) + "\n";
	sgxM2str += converter.byteArrayToHexString(smsg2.spid.id, 16) + "\n";
	sgxM2str += converter.byteArrayToHexString(lType, 1) + "\n";
	sgxM2str += converter.uint32ToLEString(smsg2.sign_gb_ga.x, 8) + "\n";
	sgxM2str += converter.uint32ToLEString(smsg2.sign_gb_ga.y, 8) + "\n";
	sgxM2str += converter.byteArrayToHexString(smsg2.mac, 16) + "\n";
	return sgxM2str;
}

//Constructor to populate an "empty" object with values that allow 
//dection of missing fields after deserialization.
ResponseM4Body::ResponseM4Body(){
	std::memcpy(platformInfo, MsgInitValues::DS_EMPTY_PIB_BA, 101);
	static uint8BYTE const PltfrmInfoRsrvd[] = { 0x00, 0x00, 0x00 };
	std::memcpy(pltfrmInfoRsrvd, PltfrmInfoRsrvd, 3);
	std::memcpy(attestationStatus, MsgInitValues::DS_EMPTY_BA4, 4);
	std::memcpy(cmacStatus, MsgInitValues::DS_EMPTY_BA16, 16);
	std::memcpy(isvCryptPayloadSize, MsgInitValues::DS_EMPTY_BA4, 4);
	std::memcpy(isvClearPayloadSize, MsgInitValues::DS_EMPTY_BA4, 4);
	std::memcpy(CryptIv, MsgInitValues::DS_EMPTY_BA12, 12);
	std::memcpy(isvPayloadTag, MsgInitValues::DS_EMPTY_BA16, 16);
	std::memcpy(isvPayload, MsgInitValues::DS_EMPTY_BA64, 64);
}

//getters and setters for M4 response fields
uint8BYTE* ResponseM4Body::getPlatformInfo() { return platformInfo; }
void  ResponseM4Body::setPlatformInfo(uint8BYTE PlatformInfo[]) { std::memcpy(platformInfo, PlatformInfo, 101); }
uint8BYTE* ResponseM4Body::getPltfrmInfoRsrvd(){ return pltfrmInfoRsrvd; }
uint8BYTE* ResponseM4Body::getAttestationStatus() { return attestationStatus; }
void  ResponseM4Body::setAttestationStatus(uint8BYTE AttestationStatus[]) { std::memcpy(attestationStatus, AttestationStatus, 4); }
uint8BYTE* ResponseM4Body::getCmacstatus() { return cmacStatus; }
void  ResponseM4Body::setCmacstatus(uint8BYTE Cmacstatus[16]) { std::memcpy(cmacStatus, Cmacstatus, 16); }
uint8BYTE* ResponseM4Body::getIsvCryptPayloadSize() { return isvCryptPayloadSize; }
void  ResponseM4Body::setIsvCryptPayloadSize(uint8BYTE IsvCryptPayloadSize[4]) { memcpy(isvCryptPayloadSize, IsvCryptPayloadSize, 4); }
uint8BYTE* ResponseM4Body::getIsvClearPayloadSize() { return isvClearPayloadSize; }
void  ResponseM4Body::setIsvClearPayloadSize(uint8BYTE IsvClearPayloadSize[4]) { memcpy(isvClearPayloadSize, IsvClearPayloadSize, 4); }
uint8BYTE *ResponseM4Body::getCryptIv(){ return CryptIv; }
void  ResponseM4Body::setCryptIv(uint8BYTE cryptIv[12]) { std::memcpy(CryptIv, cryptIv, 12); }
uint8BYTE *ResponseM4Body::getIsvPayloadTag() { return isvPayloadTag; }
void  ResponseM4Body::setIsvPayloadTag(uint8BYTE IsvPayloadTag[]) { std::memcpy(isvPayloadTag, IsvPayloadTag, 16); }
uint8BYTE *ResponseM4Body::getIsvPayload() { return isvPayload; }
void  ResponseM4Body::setIsvPayload(uint8BYTE IsvPayload[360]) { std::memcpy(isvPayload, IsvPayload, 360); }
void ResponseM4Body::getIsvKey(uint8BYTE *IsvKey) {
	std::memcpy(IsvKey, isvPayload, 32);
}
void ResponseM4Body::getIsvCert(uint8BYTE *IsvCert) {
	std::memcpy(IsvCert, isvPayload + 32, 304);
}

//Constructor to populate an "empty" object with values that allow 
//dection of missing fields after deserialization.
M4ResponseMessage::M4ResponseMessage(){
	Converter converter;
	memcpy(respHeader.protocolVer, MsgInitValues::DS_EMPTY_BA2, 2);
	memcpy(respHeader.respStatus, converter.uint32ToByteArray(enStatusCodes::RaErrUnknown), 4);
	uint8_t *p = converter.uint32ToByteArray(enMsgType::RaReserved);
	memcpy(respHeader.respType, p, 4);
	memcpy(respHeader.msgLength, converter.uint32ToByteArray(enDefaultLength::RaDefaultEmptyLength), 4);
	std::memcpy(respHeader.sessionNonce, MsgInitValues::DS_EMPTY_NONCE, 16);
	respMsg4Body = ResponseM4Body();
}

//Constructor for an actual response message
//for use as a reference or for making a real response
M4ResponseMessage::M4ResponseMessage(string respond){
	Converter converter;
	if (respond != ""){
		memcpy(respHeader.protocolVer, MsgInitValues::PROTOCOL, 2);
		memcpy(respHeader.respStatus, converter.uint32ToByteArray(enStatusCodes::RaErrNone), 4);
		uint8_t *p = converter.uint32ToByteArray(enMsgType::RaIsvPaylodResp);
		memcpy(respHeader.respType, p, 4);
		memcpy(respHeader.msgLength, converter.uint32ToByteArray(enDefaultLength::RaDefaultM4Length), 4);
		std::memcpy(respHeader.sessionNonce, MsgInitValues::ivZ16, 16);
		respMsg4Body = ResponseM4Body();
	}
	else {
		cout << "Bad parameter to M4 response Message construtor" << endl;
		AbortProcess();
	}
}

//Function that prints all the field}s of the M4 response  in a hexa decimal string format
string M4ResponseMessage::GetMsgString(){
	string m4str = "";
	Converter converter;
	m4str = converter.byteArrayToHexString(respHeader.getProtocolVer(), 2) + "\n reserved= ";
	m4str += converter.byteArrayToHexString(respHeader.reserved, 2) + "\n respstatus=";
	m4str += converter.byteArrayToHexString(respHeader.getRespStatus(), 4) + "\n resptype= ";
	m4str += converter.byteArrayToHexString(respHeader.getRespType(), 4) + "\n msglength=";
	m4str += converter.byteArrayToHexString(respHeader.getMsgLength(), 4) + "\n sessionNonce=";
	m4str += converter.byteArrayToHexString(respHeader.getSessionNonce(), 16) + "\n platformInfo = ";
	m4str += converter.byteArrayToHexString(respMsg4Body.getPlatformInfo(), 101) + "\n pltfrmInfoRsrvd= ";
	m4str += converter.byteArrayToHexString(respMsg4Body.getPltfrmInfoRsrvd(), 3) + "\n attestationstatus=";
	m4str += converter.byteArrayToHexString(respMsg4Body.getAttestationStatus(), 4) + "\n cmacstatus=";
	m4str += converter.byteArrayToHexString(respMsg4Body.getCmacstatus(), 16) + "\n isccryptpayloadsize = ";
	m4str += converter.byteArrayToHexString(respMsg4Body.getIsvCryptPayloadSize(), 4) + "\n isvClearpayloadsize=";
	m4str += converter.byteArrayToHexString(respMsg4Body.getIsvClearPayloadSize(), 4) + "\n cryptiv=  ";
	m4str += converter.byteArrayToHexString(respMsg4Body.getCryptIv(), 12) + "\n payloadTag= ";
	m4str += converter.byteArrayToHexString(respMsg4Body.getIsvPayloadTag(), 16) + "\n payload =";
	m4str += converter.byteArrayToHexString(respMsg4Body.getIsvPayload(), 360);
	return m4str;
}
