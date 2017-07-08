//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.
/*********************************************************************
FILENAME: JsonDeserialization.h
DESCRIPTION: Header file for JsonDeSerialization.cpp.
	         supports Utility functions that are used for JSON Deserialization and
             object creation during the sigma protocol process
FUNCTIONALITY:  Deserializes the receivedd JSON objects from the ISV  server and assigns them to
to a response message object of the cient
**********************************************************************/
#pragma once
#include "RaMessages.h" //To access the all the message definitions

class JsonDeserialization{
public:
	/*
	Response headers structure remains same for all the response messages.
	This method is used by all of the reponse headers to deserialize the response headers
	@Param1: Input: Pvalue1 --json response object from the ISV server
	@Param2: Output: responseMsgHeader --Pvalue1 object is Deserialized to a newly
	created Json object, the key value is compared to the message
	field name, assigned to the respective responseMsgeHeader's field.
	*/
	void deserializeRespHeader(web::json::value, ResponseMsgHeader&);

	/*
	used to deserialize the M2 Response body
	@Param1: Input: Pvalue0 --json response object from the ISV server
	@Param2: Output: responseM2BodyObj --Pvalue0 object is Deserialized to a newly
	created Json object, the key value is compared to the message
	field name, assigned to the respective M2 response body object's field.
	*/
	void deserializeM2RespBody(web::json::value, ResponseM2Body &responseM2BodyObj);

	/*
	This API deserializes the M4 Response body
	@Param1: Input: Pvalue0 --json response object from the ISV server
	@Param2: Output: responseM4Body--Pvalue0 object is Deserialized to a newly
	created Json object, the key value is compared to the message
	field name, assigned to the respective M4 response body object's field.
	*/
	void deserializeM4RespBody(web::json::value, ResponseM4Body &responseM4BodyObj);

	/*
	This routine builds a json object that will be used to create JSON
	request and response objects
	@param1 -input:the refernce parameter which is to be converted to a json object. All the 
	         data members of the messages are cretaed as json objects in this sample
	@param2 -input: the size of the refernce variable in bytes
	@param -output: an equivalent json object of the reference parameter of utility::string_t type
	*/
	utility::string_t  buildJsonObject(uint8BYTE *, int);
};

