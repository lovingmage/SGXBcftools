//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.
/******************************************************************************************
FILENAME:    RemoteAttestation.cpp
DESCRIPTION: holds the implementation of the modified sigma protocol message communication
			between the client, server, and IAS of the Remote Attestation process
*****************************************************************************/
#include "stdafx.h"
#include "ISV-APP.h"  //includes all the othe required headers including RemoteAttestation.h
#include "sgx_ukey_exchange.h" /*To call untrusted key exchange library i.e., sgx_ra_get_msg1() and sgx_ra_proc_msg2() */

using namespace std;
using namespace web;
using namespace web::http;
using namespace web::http::client;

sgx_status_t sgx_ret = SGX_SUCCESS;
int ret = 0;
MsgInitValues msgInitValues;
uint32_t extendedGID;
JsonDeserialization jsonDeserial;
//creating the references for all the messages
ResponseMsgHeader responseMsgHeader;
ChallengeResponse challengeResponse("respond");
ResponseChallengeMsgBody respChallMsgBodyObj;
M0RequestMessage m0RequestMessage("Request");
M0ResponseMessage m0ResponseMessage("Respond");
M1RequestMessage m1RequestMessage("Request");
M2ResponseMessage m2ResponseMessage("Respond");
ResponseM2Body responseM2BodyObj;
M3RequestMessage m3RequestMessage("Request");
M4ResponseMessage m4ResponseMessage("Respond");

pplx::task<int> PostProvisioningRequest() {
	return pplx::create_task([]() -> pplx::task<http_response>{

		/*
		M0 request message object for a real request. The messages are communicated in the form of json
		objects between the Service Provider and client. So actual message field values are converted into a json object field and
		then assigned to a json object here.
		*/
		ProvRequestMessage provRequestMessage("Request");

		/* The json message objects should be in the same structure with the same names as the real message structure.
		If not deserialization of the received json object with the real message structure fails.
		Hence, we create msg0 object, with reqHeader as its field, which in turn has protocolVer, reservd, .. as its fields
		*/
		web::json::value requestHeader;
		requestHeader[L"protocolVer"] = web::json::value::string(jsonDeserial.buildJsonObject(provRequestMessage.reqHeader.getProtocolVer(), 2));
		requestHeader[L"resrvd"] = web::json::value::string(jsonDeserial.buildJsonObject(provRequestMessage.reqHeader.getResrvd(), 2));
		requestHeader[L"reqType"] = web::json::value::string(jsonDeserial.buildJsonObject(provRequestMessage.reqHeader.getReqType(), 4));
		requestHeader[L"msgLength"] = web::json::value::string(jsonDeserial.buildJsonObject(provRequestMessage.reqHeader.getMsgLength(), 4));
		requestHeader[L"nonce"] = web::json::value::string(jsonDeserial.buildJsonObject(provRequestMessage.reqHeader.getNonce(), 16));
		web::json::value msg0;
		msg0[L"reqHeader"] = web::json::value(requestHeader);

		/* the provisioning request is sent as a name value pair. Json object is serialized to a string stream
		and then sent as a http request to the Service Provider*/
		utility::stringstream_t provstream;
		msg0.serialize(provstream);

		if (verbose){
			std::wcout << endl << L"Provisioning request stream string: " << provstream.str() << std::endl;
		}

		/** Fetches the Service provider URI from the App.config.txt file and uses it to send the request***/
		string completeURI = url;
		completeURI.append("api/SpMsgs/ProvisioningRequest");

		/** http_client doest not accept a std string as a parameter
		so convert a std string into wstring **/
		std::wstring serverURI(completeURI.begin(), completeURI.end());
		http_client client(serverURI);

		/** Provisioning POST request to the Service Provider **/
		return client.request(methods::POST, L"", provstream.str(), L"application/json");

		/**  Once the client request is sent to the Service Provider, it validates and sends a challenge response back
		to the client to prove its identity**/
	}).then([](http_response response) -> int{

		/*If the status code of the response is OK, then it means the Service Provider is happy with the request and is asking to
		prove the identity. In all the other cases, might be because the Service Provider is not working or the provisioning request
		is not good, the process aborts*/
		if (response.status_code() == status_codes::OK){
			cout << endl << "****** Received Challenge response******************" << endl;
			auto body = response.extract_string();
			if (verbose){
				std::wcout << endl << L"Challenge Post Response: " << body.get().c_str() << std::endl;
			}

			// Capture the JSON response string
			utility::stringstream_t cRespStream;
			cRespStream << body.get().c_str();

			/** initialize a Challenge Message JSON object with "empty" values that can be used to recognize
			if the response is altered. An object of challenge response is created by calling the constructor with no arguements
			**/
			ChallengeResponse challengeResponse;

			// Create the empty header JSON object
			web::json::value responseHeader;
			responseHeader[L"protocolVer"] = web::json::value::string(jsonDeserial.buildJsonObject(challengeResponse.respHeader.getProtocolVer(), 2));
			responseHeader[L"reserved"] = web::json::value::string(jsonDeserial.buildJsonObject(challengeResponse.respHeader.getReserved(), 2));
			responseHeader[L"respStatus"] = web::json::value::string(jsonDeserial.buildJsonObject(challengeResponse.respHeader.getRespStatus(), 4));
			responseHeader[L"respType"] = web::json::value::string(jsonDeserial.buildJsonObject(challengeResponse.respHeader.getRespType(), 4));
			responseHeader[L"msgLength"] = web::json::value::string(jsonDeserial.buildJsonObject(challengeResponse.respHeader.getMsgLength(), 4));
			responseHeader[L"sessionNonce"] = web::json::value::string(jsonDeserial.buildJsonObject(challengeResponse.respHeader.getSessionNonce(), 16));

			// Create the empty body JSON Object
			web::json::value responseBody;
			responseBody[L"reserved"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA16, 16));

			// Combine header and body into a single message object
			web::json::value challengeMsg;
			challengeMsg[L"respHeader"] = web::json::value(responseHeader);
			challengeMsg[L"cRespBody"] = web::json::value(responseBody);
			//Parse the received challenge response JSON from the stream object that contains the received JSON response.
			challengeMsg = json::value::parse(cRespStream);
			// Create another stream based on the parsed response, and view the overwritten message fields.
			// Any missing fields will show as our "empty" values.
			utility::stringstream_t receivedChallengeStream;
			challengeMsg.serialize(receivedChallengeStream);

			// At this point, the received JSON has been written to the "empty" challenge message,
			// we now need to verify that the message contents are valid; so the "empty" values should now be replaced
			// by the real values from the received challenge response.
			// We need to extract specific values to work with else where.
			web::json::value challengeVal;
			challengeVal = json::value::parse(receivedChallengeStream);
			auto cvParentIterator = challengeVal.cbegin();  // Create an iterator to step through the two level JSON
			// We know that all response messages have two parent objects: header and body,
			// and that each of these have child members; so we can have a parent iterator and a child iterator.

			const json::value &Pkey0 = cvParentIterator->first;
			const json::value &Pvalue0 = cvParentIterator->second;
			++cvParentIterator;
			const json::value &Pkey1 = cvParentIterator->first;
			const json::value &Pvalue1 = cvParentIterator->second;

			/*To step through the second level JSON, we call deserializeRespHeader() function of JsonDeserial class. It
			Deserializes the challenge response and assigns the values to the M0 response msg header.
			*/
			jsonDeserial.deserializeRespHeader(Pvalue1, responseMsgHeader);
			return 0;
			//If the response from the Service Provider is not OK, we end the process by printing an error message
		}
		else{
			std::wcout << L"challenge Post Response Error " << std::endl;
			std::wcout << L"Response Status Code: " << response.status_code() << std::endl;
			AbortProcess();
		}
		return 0;
	});
}

pplx::task<int> PostM0Request(){
	return pplx::create_task([]() -> pplx::task<http_response>{
		web::json::value ReqHeader;
		ReqHeader[L"protocolVer"] = web::json::value::string(jsonDeserial.buildJsonObject(m0RequestMessage.reqHeader.getProtocolVer(), 2));
		ReqHeader[L"reqType"] = web::json::value::string(jsonDeserial.buildJsonObject(m0RequestMessage.reqHeader.getReqType(), 4));
		ReqHeader[L"msgLength"] = web::json::value::string(jsonDeserial.buildJsonObject(m0RequestMessage.reqHeader.getMsgLength(), 4));
		ReqHeader[L"reservd"] = web::json::value::string(jsonDeserial.buildJsonObject(m0RequestMessage.reqHeader.getResrvd(), 2));
		ReqHeader[L"nonce"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMsgHeader.getSessionNonce(), 16));
		web::json::value ReqM0Body;
		ReqM0Body[L"ExtGID"] = web::json::value::string(jsonDeserial.buildJsonObject(converter.uint32ToByteArray(extendedGID), 4));
		web::json::value msg0;
		msg0[L"reqM0Body"] = web::json::value(ReqM0Body);
		msg0[L"reqHeader"] = web::json::value(ReqHeader);
		m0RequestMessage.reqHeader.setNonce(responseMsgHeader.getSessionNonce());
		utility::stringstream_t m0stream;
		msg0.serialize(m0stream);
		if (verbose){
			cout << endl << "M0 message in string format" << m0RequestMessage.GetMsgString() << endl;
			std::wcout << endl << L"M0 JSON format stream string: " << m0stream.str() << std::endl;
		}
		string completeURI = url;
		completeURI.append("api/SpMsgs/Msg0");
		std::wstring serverURI(completeURI.begin(), completeURI.end());
		http_client client(serverURI);
		cout << endl << "*** Sending M0 Request" << endl;
		return client.request(methods::POST, L"", m0stream.str(), L"application/json");
	}).then([](http_response response) -> int{
		if (response.status_code() == status_codes::OK){
			cout << "*** Got the M0 response " << endl;
			auto M0body = response.extract_string();
			if (verbose){
				std::wcout << endl << L"M0 Post Response: " << M0body.get().c_str() << std::endl;
			}
			ResponseMessage responseMessage;
			// Create the empty header JSON object
			web::json::value responseHeader;
			responseHeader[L"protocolVer"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getProtocolVer(), 2));
			responseHeader[L"reserved"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getReserved(), 2));
			responseHeader[L"respStatus"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getRespStatus(), 4));
			responseHeader[L"respType"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getRespType(), 4));
			responseHeader[L"msgLength"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getMsgLength(), 4));
			responseHeader[L"sessionNonce"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getSessionNonce(), 16));

			// Create the empty body JSON Object
			web::json::value responseM0Body;
			responseM0Body[L"ExtGID"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA4, 4));

			web::json::value M0ResponseMsg;
			M0ResponseMsg[L"respHeader"] = web::json::value(responseHeader);
			M0ResponseMsg[L"respMsg0Body"] = web::json::value(responseM0Body);
			utility::stringstream_t M0RespStream;
			M0RespStream << M0body.get().c_str();
			M0ResponseMsg = json::value::parse(M0RespStream);
			utility::stringstream_t receivedM0Stream;
			M0ResponseMsg.serialize(receivedM0Stream);
			if (verbose){
				std::wcout << endl << endl << L"parsed M0 Response:  " << receivedM0Stream.str() << endl;
			}
			web::json::value M0ResponseVal;
			M0ResponseVal = json::value::parse(receivedM0Stream);
			auto M0ParentIterator = M0ResponseVal.cbegin();
			//respHeader
			const json::value &Pkey0 = M0ParentIterator->first;
			const json::value &Pvalue0 = M0ParentIterator->second;

			//Deserializing the json response and assigning the values to the M0 response object
			jsonDeserial.deserializeRespHeader(Pvalue0, m0ResponseMessage.respHeader);
			return 0;

		} //End if status OK
		else {
			std::wcout << L"M0 Post Response Error " << std::endl;
			std::wcout << L"Response Status Code: " << response.status_code() << std::endl;
			AbortProcess();
		}
		return 0;
	});// End 
}

pplx::task<int> PostM1Request(){
	return pplx::create_task([]() -> pplx::task<http_response>{
		web::json::value ReqHeader;
		ReqHeader[L"protocolVer"] = web::json::value::string(jsonDeserial.buildJsonObject(m1RequestMessage.reqHeader.getProtocolVer(), 2));
		ReqHeader[L"reqType"] = web::json::value::string(jsonDeserial.buildJsonObject(m1RequestMessage.reqHeader.getReqType(), 4));
		ReqHeader[L"msgLength"] = web::json::value::string(jsonDeserial.buildJsonObject(m1RequestMessage.reqHeader.getMsgLength(), 4));
		ReqHeader[L"reservd"] = web::json::value::string(jsonDeserial.buildJsonObject(m1RequestMessage.reqHeader.getResrvd(), 2));
		ReqHeader[L"nonce"] = web::json::value::string(jsonDeserial.buildJsonObject(m1RequestMessage.reqHeader.getNonce(), 16));
		web::json::value ReqM1Body;
		ReqM1Body[L"gaX"] = web::json::value::string(jsonDeserial.buildJsonObject(m1RequestMessage.reqM1Body.getGaX(), 32));
		ReqM1Body[L"gaY"] = web::json::value::string(jsonDeserial.buildJsonObject(m1RequestMessage.reqM1Body.getGaY(), 32));
		ReqM1Body[L"pltfrmGid"] = web::json::value::string(jsonDeserial.buildJsonObject(m1RequestMessage.reqM1Body.getPltfrmGid(), 4));
		web::json::value msg1;
		msg1[L"reqM1Body"] = web::json::value(ReqM1Body);
		msg1[L"reqHeader"] = web::json::value(ReqHeader);

		utility::stringstream_t m1stream;
		msg1.serialize(m1stream);
		if (verbose){
			cout << endl << "M1 message in string format" << m1RequestMessage.GetMsgString() << endl;
			std::wcout << endl << L"M1 JSON format stream string: " << m1stream.str() << std::endl;
		}
		string completeURI = url;
		completeURI.append("api/SpMsgs/Msg1");
		std::wstring serverURI(completeURI.begin(), completeURI.end());
		http_client client(serverURI);
		cout << endl << "*** Sending M1 Request" << endl;
		return client.request(methods::POST, L"", m1stream.str(), L"application/json");
	}).then([](http_response response) -> int{
		if (response.status_code() == status_codes::OK){
			cout << "*** Got the M2 response " << endl;
			auto M2body = response.extract_string();
			if (verbose){
				std::wcout << endl << L"M2 Post Response: " << M2body.get().c_str() << std::endl;
			}
			ResponseMessage responseMessage;
			// Create the empty header JSON object
			web::json::value responseHeader;
			responseHeader[L"protocolVer"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getProtocolVer(), 2));
			responseHeader[L"reserved"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getReserved(), 2));
			responseHeader[L"respStatus"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getRespStatus(), 4));
			responseHeader[L"respType"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getRespType(), 4));
			responseHeader[L"msgLength"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getMsgLength(), 4));
			responseHeader[L"sessionNonce"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getSessionNonce(), 16));

			// Create the empty body JSON Object
			web::json::value responseM2Body;
			responseM2Body[L"gbX"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA32, 32));
			responseM2Body[L"gbY"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA32, 32));
			responseM2Body[L"spId"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA16, 16));
			responseM2Body[L"cmacsmk"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA16, 16));
			responseM2Body[L"sigRl"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA32, 32));
			responseM2Body[L"sigrlSize"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA4, 4));
			responseM2Body[L"sigSp"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA64, 64));
			responseM2Body[L"sigLinkType"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA4, 4));

			web::json::value M2ResponseMsg;
			M2ResponseMsg[L"respHeader"] = web::json::value(responseHeader);
			M2ResponseMsg[L"respMsg2Body"] = web::json::value(responseM2Body);

			utility::stringstream_t M2RespStream;
			M2RespStream << M2body.get().c_str();
			M2ResponseMsg = json::value::parse(M2RespStream);
			utility::stringstream_t receivedM2Stream;
			M2ResponseMsg.serialize(receivedM2Stream);

			web::json::value M2ResponseVal;
			M2ResponseVal = json::value::parse(receivedM2Stream);
			auto M2ParentIterator = M2ResponseVal.cbegin();
			//respMsg2Body
			const json::value &Pkey0 = M2ParentIterator->first;
			const json::value &Pvalue0 = M2ParentIterator->second;
			++M2ParentIterator;
			//respHeader
			const json::value &Pkey1 = M2ParentIterator->first;
			const json::value &Pvalue1 = M2ParentIterator->second;

			//Deserializing the json response and assigning the values to the M2 response object
			jsonDeserial.deserializeRespHeader(Pvalue1, m2ResponseMessage.respHeader);
			jsonDeserial.deserializeM2RespBody(Pvalue0, responseM2BodyObj);
			return 0;
		} //End if status OK
		else {
			std::wcout << L"M2 Post Response Error " << std::endl;
			std::wcout << L"Response Status Code: " << response.status_code() << std::endl;
			AbortProcess();
		}
		return 0;
	});// End receiving response 
}

pplx::task<int> PostM3Request(){
	return pplx::create_task([]() -> pplx::task<http_response>{
		/*
		cretaing JSON header and Body objects; assigning the msg3 fields to the JSON object fields
		*/
		web::json::value ReqHeader;
		ReqHeader[L"protocolVer"] = web::json::value::string(jsonDeserial.buildJsonObject(m3RequestMessage.reqHeader.getProtocolVer(), 2));
		ReqHeader[L"reqType"] = web::json::value::string(jsonDeserial.buildJsonObject(m3RequestMessage.reqHeader.getReqType(), 4));
		ReqHeader[L"msgLength"] = web::json::value::string(jsonDeserial.buildJsonObject(m3RequestMessage.reqHeader.getMsgLength(), 4));
		ReqHeader[L"reservd"] = web::json::value::string(jsonDeserial.buildJsonObject(m3RequestMessage.reqHeader.getResrvd(), 2));
		ReqHeader[L"nonce"] = web::json::value::string(jsonDeserial.buildJsonObject(m3RequestMessage.reqHeader.getNonce(), 16));

		web::json::value ReqM3Body;
		ReqM3Body[L"aesCmac"] = web::json::value::string(jsonDeserial.buildJsonObject(m3RequestMessage.reqM3Body.getAesCmac(), 16));
		ReqM3Body[L"gaX"] = web::json::value::string(jsonDeserial.buildJsonObject(m3RequestMessage.reqM3Body.getGaX(), 32));
		ReqM3Body[L"gaY"] = web::json::value::string(jsonDeserial.buildJsonObject(m3RequestMessage.reqM3Body.getGaY(), 32));
		ReqM3Body[L"secProperty"] = web::json::value::string(jsonDeserial.buildJsonObject(m3RequestMessage.reqM3Body.getSecProperty(), 256));
		ReqM3Body[L"quote"] = web::json::value::string(jsonDeserial.buildJsonObject(m3RequestMessage.reqM3Body.getQuote(), enDefaultLength::RaDefaultQuoteLength));

		web::json::value msg3;
		msg3[L"reqM3Body"] = web::json::value(ReqM3Body);
		msg3[L"reqHeader"] = web::json::value(ReqHeader);

		utility::stringstream_t m3stream;
		msg3.serialize(m3stream);
		string completeURI = url;
		completeURI.append("api/SpMsgs/Msg3");
		std::wstring serverURI(completeURI.begin(), completeURI.end());
		http_client client(serverURI);
		cout << endl << "*** Sending M3 Request" << endl;
		if (verbose){
			std::wcout << endl << L"M3 JSON format stream string: " << m3stream.str() << std::endl;
		}
		return client.request(methods::POST, L"", m3stream.str(), L"application/json");
	}).then([](http_response response) -> int{
		if (response.status_code() == status_codes::OK)	{
			cout << endl << "*** Got the M4 response " << endl;
			auto M4body = response.extract_string();
			if (verbose){
				std::wcout << endl << L"M4 Post Response: " << M4body.get().c_str() << std::endl;
			}

			ResponseMessage responseMessage;
			// Create the empty M4 JSON object to find the missing vaalues of received M4 if any
			web::json::value responseHeader;
			responseHeader[L"protocolVer"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getProtocolVer(), 2));
			responseHeader[L"reserved"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getReserved(), 2));
			responseHeader[L"respStatus"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getRespStatus(), 4));
			responseHeader[L"respType"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getRespType(), 4));
			responseHeader[L"msgLength"] = web::json::value::string(jsonDeserial.buildJsonObject(responseMessage.respHeader.getMsgLength(), 4));
			responseHeader[L"sessionNonce"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA16, 16));

			// Create the empty body JSON Object
			web::json::value responseM4Body;
			responseM4Body[L"platformInfo"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_PIB_BA, 101));
			responseM4Body[L"pltfrmInfoRsrvd"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA3, 3));
			responseM4Body[L"attestationStatus"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA4, 4));
			responseM4Body[L"cmacStatus"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA16, 16));
			responseM4Body[L"isvCryptPayloadSize"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA4, 4));
			responseM4Body[L"isvClearPayloadSize"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA4, 4));
			responseM4Body[L"CryptIv"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA12, 12));
			responseM4Body[L"isvPayloadTag"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA16, 16));
			responseM4Body[L"isvPayload"] = web::json::value::string(jsonDeserial.buildJsonObject(MsgInitValues::DS_EMPTY_BA360, 360));

			web::json::value M4ResponseMsg;
			M4ResponseMsg[L"respHeader"] = web::json::value(responseHeader);
			M4ResponseMsg[L"respMsg4Body"] = web::json::value(responseM4Body);

			utility::stringstream_t M4RespStream, receivedM4Stream;
			M4RespStream << M4body.get().c_str();
			M4ResponseMsg = json::value::parse(M4RespStream);
			M4ResponseMsg.serialize(receivedM4Stream);

			web::json::value M4ResponseVal;
			M4ResponseVal = json::value::parse(receivedM4Stream);
			auto M4ParentIterator = M4ResponseVal.cbegin();
			//respMsg4Body
			const json::value &Pkey0 = M4ParentIterator->first;
			const json::value &Pvalue0 = M4ParentIterator->second;
			++M4ParentIterator;
			//respHeader
			const json::value &Pkey1 = M4ParentIterator->first;
			const json::value &Pvalue1 = M4ParentIterator->second;
			jsonDeserial.deserializeRespHeader(Pvalue1, m4ResponseMessage.respHeader);
			int status = converter.byteArrayToInt(m4ResponseMessage.respHeader.respStatus);
			if (status == 200 || status == 201){
				jsonDeserial.deserializeM4RespBody(Pvalue0, m4ResponseMessage.respMsg4Body);
			}
			else if (status == 400){
				cout <<endl<< "M4 Post response error with status code " << status << endl 
					<<"Quote Attestation with IAS Failed. Check server logs for more info"<<endl;
				AbortProcess();
			}
			else {
				cout << "M4 Post response error with status code " << status << endl;
				AbortProcess();
			}
		}
		else {
			cout << "M4 Post response error with status code " << response.status_code() << endl;
			AbortProcess();
		}
		return 0;
	});
}

void SendProvisioningRequest(){
	wcout << endl << L"*** Sending Provisioning Request...***" << endl;
	int retry_time;
	retry_time = 0;
	bool retry;
	cout << endl << "*** Client connecting to " << url << endl;
	/* SP should be started first and then the client run should begin
	Client Tries to connect to the ISV Service Provider, if it can't connect, it gives 2 more tries and then gives up
	and the process stops.
	*/
	do{
		retry = false;
		try{
			/*A method that sends the M0 request to the SP and
			receives a challenge response from the SP */
			PostProvisioningRequest().wait();
		}
		catch (...){
			retry_time++;
			retry = true;
			cout << endl << "  Trial " << retry_time << " failed" << endl;
			if (retry_time == 3){
				std::wcout << endl << L"*** Provisioning Request Failure - JSON Exception or Service Provider May Be Offline ***" << std::endl;
				AbortProcess();
			}
		}
	} while (retry && retry_time < 3);

}
uint32_t GetExtendedGID(){
	int GID_status = 0;
	uint32_t extEPID_GID;
	GID_status = sgx_get_extended_epid_group_id(&extEPID_GID);
	if (GID_status == SGX_SUCCESS)
		cout << "extended GID = " << extEPID_GID << endl;
	else
		cout << "status is  " << GID_status << endl;
	return extEPID_GID;
}

void SendMsg1(){

	int retGIDStatus = 0;
	int count = 0;
	sgx_ra_msg1_t sgxMsg1Obj;
	//A call to generate the msg1 
	while (1){
		retGIDStatus = sgx_ra_get_msg1(context, eid, sgx_ra_get_ga, &sgxMsg1Obj);
		if (retGIDStatus == SGX_SUCCESS){
			break;
		}
		else if (retGIDStatus == SGX_ERROR_BUSY){
			if (count == 5){ //retried 5 times, so fail out
				cout << endl << "*** sgx_ra_get_msg1 is busy - 5 retries failed" << endl;
				AbortProcess();
			}
			// wait 10 seconds, then retry
			Sleep(10000);
			count++;
		}
		else{    //error other than busy
			cout << endl << "*** M1 generation failure " << endl;
			AbortProcess();
		}
	}

	cout << endl << "****** M1 generated Successfully *******" << endl;
	//copying the contents from SGX MSG1 object to M1RequestMessage object
	m1RequestMessage.reqM1Body.setGaX(sgxMsg1Obj.g_a.gx);
	m1RequestMessage.reqM1Body.setGaY(sgxMsg1Obj.g_a.gy);
	m1RequestMessage.reqM1Body.setPltfrmGid(sgxMsg1Obj.gid);

	/** Get the challenge response nonce and set it to the M1 request message;
	this proves the identity of the Application to the SP**/
	m1RequestMessage.reqHeader.setNonce(responseMsgHeader.getSessionNonce());
	if (verbose){
		cout << "  GID= " << converter.byteArrayToHexString(m1RequestMessage.reqM1Body.getPltfrmGid(), 4) << endl;
	}
	/**  Post the M1 request message to the ISV Service Provider and receive
	M2 as a response. If there is an error in sending or rceiving the messages to
	the Service Provider, an exception is thrown
	**/
	try{
		PostM1Request().wait();
	}
	catch (...){
		std::wcout << endl << L"*** M1 Failure - JSON Exception or Service Provider May Be Offline ***" << std::endl;
		AbortProcess();
	}

}
void SendMsg0(){

	try{
		PostM0Request().wait();
	}
	catch (...){
		std::wcout << endl << L"*** M0 Failure - JSON Exception or Service Provider May Be Offline ***" << std::endl;
		AbortProcess();
	}
}
void ProcessMsg2AndSendMsg3(){
	m2ResponseMessage.setRespMsg2Body(responseM2BodyObj);
	/*
	To generate Msg3, sgx defined Msg2 struture should be passed as
	one of the paramters to the high level wrapper function, sgx_ra_proc_msg2(). So
	each field of the received M2 response object is assigned to sgx_ra_msg2 object;
	*/

	//sgx msg3 object 
	sgx_ra_msg3_t *sgx_msg3 = NULL;
	uint32_t msg3_size = 0;
	//sigRl size
	uint32_t sig_rl_size = (m2ResponseMessage.respMsg2Body.getSigrlSize()[0]) |
		(m2ResponseMessage.respMsg2Body.getSigrlSize()[1] << 8) |
		(m2ResponseMessage.respMsg2Body.getSigrlSize()[2] << 16) |
		(m2ResponseMessage.respMsg2Body.getSigrlSize()[3] << 24);

	if (sig_rl_size < 0 || sig_rl_size > 32){
		cout << "Bad SigRL" << endl;
		AbortProcess();
	}
	sgx_ra_msg2_t * sgx_ra_msg2_obj = (sgx_ra_msg2_t*)malloc(sizeof(sgx_ra_msg2_t) + sig_rl_size);
	SGXM2ResponseMessage sgxM2respObj;

	//gbX & gbY
	memcpy(sgx_ra_msg2_obj->g_b.gx, m2ResponseMessage.respMsg2Body.getGbX(), 32);
	memcpy(sgx_ra_msg2_obj->g_b.gy, m2ResponseMessage.respMsg2Body.getGbY(), 32);

	//SPID  
	memcpy(sgx_ra_msg2_obj->spid.id, m2ResponseMessage.respMsg2Body.getSpId(), 16);

	//Link type
	uint8BYTE link[2];
	memcpy(link, m2ResponseMessage.respMsg2Body.getSigLinkType(), 2);

	/*
	If 0 is received as a link type, then it is an unlinkable Quote
	else it is a linkable quote.
	*/
	int link_int = link[0];
	if (link_int == 0)
		sgx_ra_msg2_obj->quote_type = SGX_UNLINKABLE_SIGNATURE;
	else
		sgx_ra_msg2_obj->quote_type = SGX_LINKABLE_SIGNATURE;

	//kdfId
	uint8BYTE kdfid[2];
	memcpy(kdfid, m2ResponseMessage.respMsg2Body.getKdfId(), 2);
	uint16_t kdfid16 = kdfid[0] | kdfid[1] << 8;
	sgx_ra_msg2_obj->kdf_id = kdfid16;

	//sigSP
	memcpy(sgx_ra_msg2_obj->sign_gb_ga.x, m2ResponseMessage.respMsg2Body.getSigSpX(), 32);
	memcpy(sgx_ra_msg2_obj->sign_gb_ga.y, m2ResponseMessage.respMsg2Body.getSigSpY(), 32);

	//cmac
	memcpy(sgx_ra_msg2_obj->mac, m2ResponseMessage.respMsg2Body.getCmacsmk(), 16);

	uint8BYTE sigRl[32];
	memcpy(sigRl, m2ResponseMessage.respMsg2Body.getSigRl(), 32);
	for (uint32_t i = 0; i < sig_rl_size; i++){
		memcpy((uint8_t *)sgx_ra_msg2_obj->sig_rl[i], (uint8_t *)sigRl[i], sig_rl_size);
	}

	sgx_ra_msg2_obj->sig_rl_size = sig_rl_size;
	uint32_t msg2Size = sizeof(sgx_ra_msg2_t);// + sgx_ra_msg2_obj.sig_rl_size;
	string sgxMsg2 = sgxM2respObj.GetSGXMsg2String(*sgx_ra_msg2_obj);

	//high level wrapper function that process the msg2 and if validated, generates M3
	ret = sgx_ra_proc_msg2(context, eid, sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, sgx_ra_msg2_obj, msg2Size, &sgx_msg3, &msg3_size);

	if (ret != SGX_SUCCESS){
		cout << endl << "*****M2 process to generate M3 is a failure, with error code:  " << ret << endl;
		AbortProcess();
	}
	cout << endl << "******** Generated M3 successfully*****" << endl;
	/*M3 message length is set to the generated sgx msg3 object + the size of the request header*/
	int reqMsgHeaderSize = sizeof(ReqMsgHeader);
	uint32_t tSize = msg3_size + (uint32_t)reqMsgHeaderSize;
	uint8BYTE M3MsgLen[4] = { 0x00 };
	std::memcpy(M3MsgLen, converter.uint32ToByteArray(tSize), 4);

	m3RequestMessage.reqHeader.setMsgLength(M3MsgLen);
	m3RequestMessage.reqHeader.setNonce(m2ResponseMessage.respHeader.getSessionNonce());
	m3RequestMessage.reqM3Body.setAesCmac(sgx_msg3->mac);
	m3RequestMessage.reqM3Body.setGaX(sgx_msg3->g_a.gx);
	m3RequestMessage.reqM3Body.setGaY(sgx_msg3->g_a.gy);
	m3RequestMessage.reqM3Body.setSecProperty(sgx_msg3->ps_sec_prop.sgx_ps_sec_prop_desc);
	m3RequestMessage.reqM3Body.setQuote(sgx_msg3->quote);

	free(sgx_ra_msg2_obj);
	free(sgx_msg3);

	//post M3 request message and receive M4 response from the service provider
	try{
		PostM3Request().wait();
	}
	catch (...){
		std::cout << endl << L"*** M3 Failure - JSON Exception or Service Provider May Be Offline ***" << endl;
		AbortProcess();
	}
}

void ProcessMsg4() {

	uint8BYTE *respStatus = m4ResponseMessage.respHeader.getRespStatus();
	string respStr = converter.byteArrayToHexString(respStatus, 4);
	if (memcmp(respStatus, converter.uint32ToByteArray(enStatusCodes::RaErrIasCreated), 4) == 0)
		cout << endl << "**** M4 response Status 201: Create Report successful from IAS" << endl;
	else if (memcmp(respStatus, converter.uint32ToByteArray(enStatusCodes::RaErrIasBadRequest), 4) == 0){
		cout << endl << "*** M4 response Status 400: Invalid Evidence Payload from IAS" << endl;
		AbortProcess();
	}
	else if (memcmp(respStatus, converter.uint32ToByteArray(enStatusCodes::RaErrIasUnauth), 4) == 0){
		cout << endl << "*** M4 response Status 401: Unauthorized response from IAS" << endl;
		AbortProcess();
	}
	else if (memcmp(respStatus, converter.uint32ToByteArray(enStatusCodes::RaErrIasInternal), 4) == 0){
		cout << endl << "*** M4 response Status 500: Internal Error from IAS" << endl;
		AbortProcess();
	}
	else if (memcmp(respStatus, converter.uint32ToByteArray(enStatusCodes::RaErrIasUnknown), 4) == 0){
		cout << endl << "*** M4 response Status 520: Unknown IAS Error or Connection Error" << endl;
		AbortProcess();
	}
	else if (memcmp(respStatus, converter.uint32ToByteArray(enStatusCodes::RaErrIasNotFound), 4) == 0){
		cout << endl << "*** M4 response Status 404: Not Found response from IAS" << endl;
		AbortProcess();
	}

	ResponseM4Body * m = &m4ResponseMessage.respMsg4Body;
	sgx_status_t attestation_status = SGX_ERROR_INVALID_ENCLAVE;
	int payloadLength = converter.byteArrayToInt(m->isvCryptPayloadSize) + converter.byteArrayToInt(m->isvClearPayloadSize);
	int cryptPayloadSize = converter.byteArrayToInt(m->isvCryptPayloadSize);

	// At this point, msg4 is received. Send it to the enclave to validate, look at status, and obtain secrets
	ret = process_RA_status(eid, &attestation_status, context, m->attestationStatus, m->cmacStatus, m->isvPayload,
		payloadLength, cryptPayloadSize, m->CryptIv, sealedSecret);
	if (ret == SGX_ERROR_ENCLAVE_LOST){
		DestroyAndCreateEnclave();
		ret = process_RA_status(eid, &attestation_status, context, m->attestationStatus, m->cmacStatus, m->isvPayload,
			payloadLength, cryptPayloadSize, m->CryptIv, sealedSecret);
	}
	if (attestation_status == SGX_SUCCESS){
		cout << endl << "*** Decrypted the ISV key sucessfully ***" << endl;
		uint32_t leaseDuration = (*(uint32_t*)&m4ResponseMessage.respMsg4Body.attestationStatus[0]) >> 8;
		cout << endl << "*** Remote Attestation: Lease duration = " << leaseDuration << " seconds" << endl;

		// the client writes the sealed secret to a file for later use */
		// Sealed secret is invalid if we don't have a trusted time source, so don't store it if b_pse = false
		WriteToFile();
		cout << endl << "*** Wrote sealed secret to a file successfully ****" << endl;
	}
	else if (attestation_status == TEMPORARY_TRUST){
		if (b_pse){
			cout << endl << "*** Remote Attestation: Server trusts Client Enclave but PSE isn't trusted or duration = 0" << endl;
			cout << "   Secret can only be used for one EncryptDecrypt operation before reattestation required." << endl;
			// Stop using trusted time
			b_pse = false;
		}
		else{
			cout << "*** No trusted services for rest of the program - Secret can only be used for one EncryptDecrypt operation before reattestation required." << endl;
		}
	}
	else{
		cout << endl << "**** Attestation was not successful. Status = " << attestation_status << endl;
		AbortProcess();
	}

	if (m4ResponseMessage.respMsg4Body.attestationStatus[0] < 4){
		cout << "No PIB was received from RA Server. No issues found." << endl;
	}
	else{
		sgx_platform_info_t sgxPltObj;
		memcpy(sgxPltObj.platform_info, m4ResponseMessage.respMsg4Body.getPlatformInfo(), 101);

		/**
		Examine PIB to see what action to take to remediate any issues.
		*/
		sgx_update_info_bit_t update_info;
		int count = 0;
		while (1){
			ret = sgx_report_attestation_status(&sgxPltObj, (attestation_status == SGX_SUCCESS) ? 0 : 1, &update_info);
			if (ret == SGX_SUCCESS){
				cout << "PIB was received but SGX Platform Software sees no action needed" << endl;
				break;
			}
			else if (ret == SGX_ERROR_SERVICE_TIMEOUT){
				if (count == 5){
					cout << "sgx_report_attestation_status: Timeout error - 5 retries unsuccessful" << endl;
					AbortProcess();
				}
				else{
					// wait 10 seconds, then retry
					Sleep(10000);
					count++;
				}
			}
			else{
				break;
			}
		}
		if (ret != SGX_SUCCESS){
			switch (ret){
			case SGX_ERROR_INVALID_PARAMETER:
				cout << "Invalid parameters" << endl;
				break;
			case SGX_ERROR_AE_INVALID_EPIDBLOB:
				cout << "EPID blob is corrupt" << endl;
				break;
			case SGX_ERROR_EPID_MEMBER_REVOKED:
				cout << "EPID group membership has been revoked. The platform is not trusted." << endl;
				cout << "Updating the platform and retrying will not remedy the revocation." << endl;
				break;
			case SGX_ERROR_UPDATE_NEEDED:
				if (update_info.pswUpdate)
					cout << "SGX: Platform Software needs to be updated" << endl;
				if (update_info.csmeFwUpdate)
					cout << "SGX: CSME needs to be updated" << endl;
				if (update_info.ucodeUpdate)
					cout << "SGX: ucode needs to be updated" << endl;
				if (update_info.pswUpdate == 0 && update_info.csmeFwUpdate == 0 &&
					update_info.ucodeUpdate == 0)
					cout << "SGX: update needed but details unclear" << endl;
				break;
			case SGX_ERROR_OUT_OF_MEMORY:
				cout << "Not enough memory is available to complete this operation." << endl;
				break;
			case SGX_ERROR_SERVICE_UNAVAILABLE:
				cout << "The AE service did not respond." << endl;
				break;
			case SGX_ERROR_NETWORK_FAILURE:
				cout << "Network connecting or proxy setting issue was encountered." << endl;
				break;
			case SGX_ERROR_UNEXPECTED:
			default:
				cout << "An unexpected error was detected." << endl;
				break;
			}
			// Remove sealed file if it exists
			if (attestation_status != TEMPORARY_TRUST){
				RemoveFile();
				AbortProcess();
			}
		}
	}
}

bool RemoteAttestation(){
	sgx_status_t sgx_ret;

	//Enclave RA session initialiation
	sgx_status_t ret = enclave_init_ra(eid, &sgx_ret, b_pse, &context);
	if (ret == SGX_ERROR_ENCLAVE_LOST){
		DestroyAndCreateEnclave();
		ret = enclave_init_ra(eid, &sgx_ret, b_pse, &context);
	}
	if (SGX_SUCCESS != ret){
		std::cout << endl << "*** Error, Enclave RA Initialization failed ***" << endl;
		AbortProcess();
	}
	SendProvisioningRequest();
	extendedGID = GetExtendedGID();
	SendMsg0();
	SendMsg1();
	ProcessMsg2AndSendMsg3();
	// RA session is closed during ProcessMsg4()
	ProcessMsg4();
	return true;
}//end of RemoteAttestation
