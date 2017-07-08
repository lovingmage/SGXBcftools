//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved
/**************************************************************************************************
FILENAME:       JsonDeserialization.cpp
DESCRIPTION:   JsonDeserialization.h is the header file. We use JSON to communicate between the client and
               server. Used to deserialize reponse messages and to build the JSON objects. 
******************************************************************************************************/

#include "stdafx.h"
#include "JsonDeserialization.h"
using namespace utility; // to access conversions::from_base64, string_t function

void JsonDeserialization::deserializeRespHeader(web::json::value Pvalue1, ResponseMsgHeader &responseMsgHeader){
	/* In Json data strucure, the data is stored as name, value pairs. The received response Json object
	is deserialized and set to a response object
	*/
	utility::string_t r, s, p, rs, rt, m;
	r = U("reserved");
	s = U("sessionNonce");
	p = U("protocolVer");
	rs = U("respStatus");
	rt = U("respType");
	m = U("msgLength");

	std::vector<uint8BYTE> res, pVer, rStatus, rType, mLen, sNonce;

	for (auto cvChildIterator = Pvalue1.cbegin();
		cvChildIterator != Pvalue1.cend(); cvChildIterator++){
		/*
		The order of the incoming responsve fields might vary for rach run,
		so by brute force method, each field is compared to the actual field names
		and then are assigned to different reponse object fields respectively
		*/

		const web::json::value &Ckey = cvChildIterator->first;
		utility::string_t c = Ckey.as_string();
		if (c.compare(r) == 0){
			const web::json::value &reservedVal = cvChildIterator->second;
			res = utility::conversions::from_base64(reservedVal.as_string());
			uint8BYTE* reser = &res[0];
			continue;
		}
		else if (c.compare(rt) == 0){
			const web::json::value &respTypeVal = cvChildIterator->second;
			rType = utility::conversions::from_base64(respTypeVal.as_string());
			uint8BYTE* rTyp = &rType[0];
			responseMsgHeader.setRespType(rTyp);
			continue;
		}
		else if (c.compare(m) == 0){
			const web::json::value &msgLengthVal = cvChildIterator->second;
			mLen = utility::conversions::from_base64(msgLengthVal.as_string());
			uint8BYTE* mLeng = &mLen[0];
			responseMsgHeader.setMsgLength(mLeng);
			continue;
		}
		else if (c.compare(p) == 0){
			const web::json::value &protVerVal = cvChildIterator->second;
			pVer = utility::conversions::from_base64(protVerVal.as_string());
			uint8BYTE* pVers = &pVer[0];
			responseMsgHeader.setProtocolVer(pVers);
			continue;
		}
		else if (c.compare(rs) == 0){
			const web::json::value &respStatuseVal = cvChildIterator->second;
			rStatus = utility::conversions::from_base64(respStatuseVal.as_string());
			uint8BYTE* reStatus = &rStatus[0];
			responseMsgHeader.setRespStatus(reStatus);
			continue;
		}
		else if (c.compare(s) == 0){
			const web::json::value &sessionNonceVal = cvChildIterator->second;
			sNonce = utility::conversions::from_base64(sessionNonceVal.as_string());
			uint8BYTE* sessNonce = &sNonce[0];
			responseMsgHeader.setSessionNonce(sessNonce);
			continue;
		}
	}
}

void JsonDeserialization::deserializeM2RespBody(web::json::value Pvalue0, ResponseM2Body &responseM2BodyObj){
	utility::string_t gbX, gbY, spID, sigLinkType, kdfId, sigSpX, sigSpY, cmacSmk, sigRl, sigrlSize;
	gbX = U("gbX");
	gbY = U("gbY");
	spID = U("spId");
	sigLinkType = U("sigLinkType");
	kdfId = U("kdfId");
	sigSpX = U("sigSpX");
	sigSpY = U("sigSpY");
	cmacSmk = U("cmacsmk");
	sigRl = U("sigRl");
	sigrlSize = U("sigrlSize");
	std::vector<uint8BYTE> vGbX, vGbY, vSpID, vSigLinkType, vKdfId, vSigSpX, vSigSpY, vCmacSmk, vSigRl, sigRlSize;
	for (auto m2ChildIterator = Pvalue0.cbegin();
		m2ChildIterator != Pvalue0.cend(); m2ChildIterator++){
		const web::json::value &Ckey = m2ChildIterator->first;
		utility::string_t c = Ckey.as_string();

		if (c.compare(gbX) == 0){
			const web::json::value &gbXVal = m2ChildIterator->second;
			vGbX = utility::conversions::from_base64(gbXVal.as_string());
			uint8BYTE* GbXVal = &vGbX[0];
			responseM2BodyObj.setGbX(GbXVal);
			continue;
		}
		else if (c.compare(gbY) == 0){
			const web::json::value &gbYVal = m2ChildIterator->second;
			vGbY = utility::conversions::from_base64(gbYVal.as_string());
			uint8BYTE* GbYVal = &vGbY[0];
			responseM2BodyObj.setGbY(GbYVal);
			continue;
		}
		else if (c.compare(spID) == 0){
			const web::json::value &spIDVal = m2ChildIterator->second;
			vSpID = utility::conversions::from_base64(spIDVal.as_string());
			uint8BYTE* SpIDVal = &vSpID[0];
			responseM2BodyObj.setSpId(SpIDVal);
			continue;
		}
		else if (c.compare(sigLinkType) == 0){
			const web::json::value &sigLinkTypeVal = m2ChildIterator->second;
			vSigLinkType = utility::conversions::from_base64(sigLinkTypeVal.as_string());
			responseM2BodyObj.setSigLinkType(&vSigLinkType[0]);
			continue;
		}
		else if (c.compare(kdfId) == 0){
			const web::json::value &kdfIdVal = m2ChildIterator->second;
			vKdfId = utility::conversions::from_base64(kdfIdVal.as_string());
			responseM2BodyObj.setKdfId(&vKdfId[0]);
			continue;
		}
		else if (c.compare(sigSpX) == 0){
			const web::json::value &sigSpXVal = m2ChildIterator->second;
			vSigSpX = utility::conversions::from_base64(sigSpXVal.as_string());
			responseM2BodyObj.setSigSpX(&vSigSpX[0]);
			continue;
		}
		else if (c.compare(sigSpY) == 0){
			const web::json::value &sigSpYVal = m2ChildIterator->second;
			vSigSpY = utility::conversions::from_base64(sigSpYVal.as_string());
			responseM2BodyObj.setSigSpY(&vSigSpY[0]);
			continue;
		}
		else if (c.compare(cmacSmk) == 0){
			const web::json::value &cmacSmkVal = m2ChildIterator->second;
			vCmacSmk = utility::conversions::from_base64(cmacSmkVal.as_string());
			responseM2BodyObj.setCmacsmk(&vCmacSmk[0]);
			continue;
		}
		else if (c.compare(sigRl) == 0){
			const web::json::value &sigRlVal = m2ChildIterator->second;
			if (!sigRlVal.is_null()){
				vSigRl = utility::conversions::from_base64(sigRlVal.as_string());
				uint8BYTE* sigRl = &vSigRl[0];
				responseM2BodyObj.setSigRl(sigRl);
			}
			continue;
		}

		else if (c.compare(sigrlSize) == 0){
			const web::json::value &sigrlSizeVal = m2ChildIterator->second;
			sigRlSize = utility::conversions::from_base64(sigrlSizeVal.as_string());
			uint8BYTE* sRlSize = &sigRlSize[0];
			responseM2BodyObj.setSigrlSize(sRlSize);
			continue;
		}

	}
}

void JsonDeserialization::deserializeM4RespBody(web::json::value Pvalue0, ResponseM4Body &responseM4BodyObj){
	utility::string_t platformInfo = U("platformInfo");
	utility::string_t pltfrmInfoRsrvd = U("pltfrmInfoRsrvd");
	utility::string_t attestationStatus = U("attestationStatus");
	utility::string_t cmacStatus = U("cmacStatus");
	utility::string_t isvCryptPayloadSize = U("isvCryptPayloadSize");
	utility::string_t isvClearPayloadSize = U("isvClearPayloadSize");
	utility::string_t CryptIv = U("CryptIv");
	utility::string_t isvPayloadTag = U("isvPayloadTag");
	utility::string_t isvPayload = U("isvPayload");
	std::vector<uint8BYTE> vPlatformInfo, vAttestationStatus, vCmacStatus, vCryptIv, vIsvPayloadTag, vCryptPayloadSize, vIsvClearPayloadSize, vIsvPayload;
	for (auto m4ChildIterator = Pvalue0.cbegin();
		m4ChildIterator != Pvalue0.cend(); m4ChildIterator++){
		const web::json::value &Ckey = m4ChildIterator->first;
		utility::string_t c = Ckey.as_string();
		if (c.compare(platformInfo) == 0){
			if (!m4ChildIterator->second.is_null()){
				const web::json::value &platformInfoVal = m4ChildIterator->second;
				vPlatformInfo = utility::conversions::from_base64(platformInfoVal.as_string());
				uint8BYTE* PlatformInfoVal = &vPlatformInfo[0];
				responseM4BodyObj.setPlatformInfo(PlatformInfoVal);
			}
			continue;
		}
		else if (c.compare(attestationStatus) == 0){
			const web::json::value &attestationStatusVal = m4ChildIterator->second;
			vAttestationStatus = utility::conversions::from_base64(attestationStatusVal.as_string());
			uint8BYTE* AttestStatusVal = &vAttestationStatus[0];
			responseM4BodyObj.setAttestationStatus(AttestStatusVal);
			continue;
		}
		else if (c.compare(cmacStatus) == 0){
			const web::json::value &cmacStatusVal = m4ChildIterator->second;
			vCmacStatus = utility::conversions::from_base64(cmacStatusVal.as_string());
			uint8BYTE* CmacStatusVal = &vCmacStatus[0];
			responseM4BodyObj.setCmacstatus(CmacStatusVal);
			continue;
		}
		else if (c.compare(isvCryptPayloadSize) == 0){
			const web::json::value &isvCryptPayloadSizeVal = m4ChildIterator->second;
			vCryptPayloadSize = utility::conversions::from_base64(isvCryptPayloadSizeVal.as_string());
			responseM4BodyObj.setIsvCryptPayloadSize(&vCryptPayloadSize[0]);
			continue;
		}
		else if (c.compare(isvClearPayloadSize) == 0){
			const web::json::value &isvCleartPayloadSizeVal = m4ChildIterator->second;
			vIsvClearPayloadSize = utility::conversions::from_base64(isvCleartPayloadSizeVal.as_string());
			responseM4BodyObj.setIsvClearPayloadSize(&vIsvClearPayloadSize[0]);
			continue;
		}
		else if (c.compare(CryptIv) == 0){
			const web::json::value &cryptIvVal = m4ChildIterator->second;
			vCryptIv = utility::conversions::from_base64(cryptIvVal.as_string());
			uint8BYTE* CryptIvVal = &vCryptIv[0];
			responseM4BodyObj.setCryptIv(CryptIvVal);
			continue;
		}
		else if (c.compare(isvPayloadTag) == 0){
			const web::json::value &isvPayloadTagVal = m4ChildIterator->second;
			vIsvPayloadTag = utility::conversions::from_base64(isvPayloadTagVal.as_string());
			uint8BYTE* IsvPayloadTagVal = &vIsvPayloadTag[0];
			responseM4BodyObj.setIsvPayloadTag(IsvPayloadTagVal);
			continue;
		}
		else if (c.compare(isvPayload) == 0){
			const web::json::value &isvPayloadVal = m4ChildIterator->second;
			vIsvPayload = utility::conversions::from_base64(isvPayloadVal.as_string());
			uint8BYTE* IsvPayloadVal = &vIsvPayload[0];
			responseM4BodyObj.setIsvPayload(IsvPayloadVal);
			continue;
		}
	}
}

utility::string_t JsonDeserialization::buildJsonObject(uint8BYTE *value, int size){
	uint8BYTE *nncArray = new uint8BYTE[size];
	memcpy(nncArray, value, size);
	std::vector<uint8BYTE> nncArrayBytes((uint8BYTE *)nncArray, &((uint8BYTE *)nncArray)[size]);
	utility::string_t jnncString = conversions::to_base64(nncArrayBytes);
	return jnncString;
}