//  Copyright (C) Intel Corporation, 2015 All Rights Reserved.

/**************************************************************************************************
FILENAME:       RemoteAttestation.h
DESCRIPTION:    Header file for RemoteAttestation.cpp, defining Remote attestation session
******************************************************************************************************/
#pragma once

#include "JsonDeserialization.h"
/**
As part of the sigma protocol multiple messages are exchanged between
ISV app and Service provider. This is the first message in that sequence. If a secret is not yet provisionied, a provision request is sent to SP from
ISV app and this function implements the HTTP POST message using the Microsoft Parallel patterns Library (pplx).
If the SP is happy with the provisioning request, it sends a challenge response to prove the identity of the application, if not the process aborts

client -------- Provision Request ----------------> SP
Client <---ChallengeResponse -------SP
**/
pplx::task<int> PostProvisioningRequest();

/**
At this point, client received a challenge response from the service provider to prove its identity.
client finds the extended GID and sends it to the server through Msg0 request. At the server the extended GID is validated
and sent back to the client as M0 response
*/
pplx::task<int> PostM0Request();

/**
At this point, client received the challenge response from the Service Provider to prove its identity,
client uses the nonce field that it received from SP along with other M1 fields to frame M1
and send M1 as a request. At the SP side, these fields are checked to validate the Message 1 anf if it is happy with the M1 request,
it sends a valid M2 response. If not, an error message is received.

Client ---->--M1 (GID,ga)-------------------------------------------------------------------------------> Service Provider
Client <------M2(gb||SPID||TYPE||SigSP(gb||ga)||CMACsmk(gb||SPID||TYPE||SigSP(gb||ga))||SigRL)----------<------ Service Provider
**/
pplx::task<int> PostM1Request();

/*
At this point, client received a valid M2 as reponse; and is sending a M3 to receive M4
Using the received M2, Client generates M3 using a high level wrapper function, sends it to the service provider.
SP validates received M3 and sends M4 to the client
Client ---->---------M3(CMACsmk(ga||PSSecProp||QUOTE)||ga||PSSecProp||QUOTE)----------------> Service Provider
Client <-----------------------------M4 with secret----------------------------<------------- Service Provider
*/

pplx::task<int> PostM3Request();

/* This function is run as the very first step in the attestation process to check the device status;
query the status of the SGX device.If not enabled before, enable it. If the device is not enabled,
SGX device not found error is expected when the enclave is created
*/
void SendProvisioningRequest();

/* Finding the value of extended GID that is sent through M0 to server by ISV-APP*/
uint32_t GetExtendedGID();

void SendMsg0();
void SendMsg1();
void ProcessMsg2AndSendMsg3();
void ProcessMsg4();
bool RemoteAttestation();