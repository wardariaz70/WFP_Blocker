#include <windows.h>
#include <fwpmu.h>
#include <fwpvi.h>
#include <stdio.h>
#include <conio.h>
#include <iostream>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")
// 5fb216a8-e2e8-4024-b853-391a4168641e
const GUID PROVIDER_KEY =
{
 0x5fb216a8,
 0xe2e8,
 0x4024,
 { 0xb8, 0x53, 0x39, 0x1a, 0x41, 0x68, 0x64, 0x1e }
};
#define EXIT_ON_ERROR(fnName) \
 if (result != ERROR_SUCCESS) \
 { \
 printf(#fnName " = 0x%08X\n", result); \
 goto CLEANUP; \
 }
unsigned long inet_addrW(__in PCWSTR cp)
{
	size_t converted;
	char mbstr[sizeof("255.255.255.255")];
	errno_t cerr;
	cerr = wcstombs_s(&converted, mbstr, sizeof(mbstr), cp, wcslen(cp));
	return (cerr == 0) ? inet_addr(mbstr) : INADDR_NONE;
}
// Helper function to delete an SA context and the associated transport
// filters.
void DeleteSaContextAndFilters(
	__in HANDLE engine,
	__in UINT64 inFilterId,
	__in UINT64 outFilterId,
	__in UINT64 saId)
{
	DWORD result;
	// Allow the LUIDs to be zero, so we can use this function to cleanup
	// partial results.
	if (saId != 0)
	{
		result = IPsecSaContextDeleteById0(engine, saId);
		if (result != ERROR_SUCCESS)
		{
			// There's not much we can do if delete fails, so continue trying

				// clean up the remaining objects.
			printf("IPsecSaContextDeleteById0 = 0x%08X\n", result);
		}
	}
	if (outFilterId != 0)
	{
		result = FwpmFilterDeleteById0(engine, outFilterId);
		if (result != ERROR_SUCCESS)
		{
			printf("FwpmFilterDeleteById0 = 0x%08X\n", result);
		}
	}
	if (inFilterId != 0)
	{
		result = FwpmFilterDeleteById0(engine, inFilterId);
		if (result != ERROR_SUCCESS)
		{
			printf("FwpmFilterDeleteById0 = 0x%08X\n", result);
		}
	}
}




DWORD InitFilterConditions(
	__in_opt PCWSTR appPath,
	__in_opt const SOCKADDR* localAddr,
	__in_opt const SOCKADDR* remoteAddr, // Add remote address parameter
	__in_opt UINT8 ipProtocol,
	__in UINT32 numCondsIn,
	__out_ecount_part(numCondsIn, *numCondsOut)
	FWPM_FILTER_CONDITION0* conds,
	__out UINT32* numCondsOut,
	__deref_out FWP_BYTE_BLOB** appId
)
{
	DWORD result = NO_ERROR;
	UINT32 numConds = 0;
	UINT16 port;
	void* addr;
	*numCondsOut = 0;
	if (localAddr != NULL)
	{
		//port = INETADDR_PORT(localAddr);
		const SOCKADDR_IN* ipv4 = reinterpret_cast<const SOCKADDR_IN*>(localAddr);
		port= ntohs(ipv4->sin_port);
		if (port != 0)
		{
			if (numConds >= numCondsIn)
			{
				result = ERROR_INSUFFICIENT_BUFFER;
				goto CLEANUP;
			}
			conds[numConds].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
			conds[numConds].matchType = FWP_MATCH_EQUAL;
			conds[numConds].conditionValue.type = FWP_UINT16;
			// The SOCKADDR struct has the port in network order, but the
			// filtering engine expects it in host order.
			conds[numConds].conditionValue.uint16 = ntohs(port);
			++numConds;
		}
		//if (!INETADDR_ISANY(localAddr))
		const sockaddr_in* ipv4Addr = reinterpret_cast<const sockaddr_in*>(localAddr);
		if (ipv4Addr->sin_addr.s_addr != INADDR_ANY)
		{
			if (numConds > numCondsIn)
			{
				result = ERROR_INSUFFICIENT_BUFFER;
				goto CLEANUP;
			}
			const sockaddr_in* ipv4Addr = reinterpret_cast<const sockaddr_in*>(localAddr);
			void* addr = (void*)&ipv4Addr->sin_addr;

			conds[numConds].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
			conds[numConds].matchType = FWP_MATCH_EQUAL;
			if (localAddr->sa_family == AF_INET)
			{
				conds[numConds].conditionValue.type = FWP_UINT32;
				// The SOCKADDR struct has the port in network order, but the
				// filtering engine expects it in host order.
				conds[numConds].conditionValue.uint32 = ntohl(*(ULONG*)addr);
			}
			else
			{
				conds[numConds].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
				conds[numConds].conditionValue.byteArray16 =
					(FWP_BYTE_ARRAY16*)addr;
			}
			++numConds;
		}
	}
	/////new code for remote //////
	if (remoteAddr != NULL)
	{
		// Set condition for remote port
		port = ntohs(reinterpret_cast<const sockaddr_in*>(remoteAddr)->sin_port);
		if (port != 0)
		{
			if (numConds >= numCondsIn)
			{
				result = ERROR_INSUFFICIENT_BUFFER;
				goto CLEANUP;
			}
			conds[numConds].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
			conds[numConds].matchType = FWP_MATCH_EQUAL;
			conds[numConds].conditionValue.type = FWP_UINT16;
			conds[numConds].conditionValue.uint16 = port;
			++numConds;
		}

		// Set condition for remote address
		const sockaddr_in* ipv4Addr = reinterpret_cast<const sockaddr_in*>(remoteAddr);
		if (ipv4Addr->sin_addr.s_addr != INADDR_ANY)
		{
			if (numConds >= numCondsIn)
			{
				result = ERROR_INSUFFICIENT_BUFFER;
				goto CLEANUP;
			}
			void* addr = (void*)&ipv4Addr->sin_addr;
			conds[numConds].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
			conds[numConds].matchType = FWP_MATCH_EQUAL;
			conds[numConds].conditionValue.type = FWP_UINT32;
			conds[numConds].conditionValue.uint32 = ntohl(*(ULONG*)addr);
			++numConds;
		}
	}
	/////END new code for remote ////
	if (ipProtocol != 0)
	{
		if (numConds >= numCondsIn)
		{
			result = ERROR_INSUFFICIENT_BUFFER;
			goto CLEANUP;
		}
		conds[numConds].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
		conds[numConds].matchType = FWP_MATCH_EQUAL;
		conds[numConds].conditionValue.type = FWP_UINT8;
		conds[numConds].conditionValue.uint8 = ipProtocol;
		++numConds;
	}
	if (appPath != NULL)
	{
		if (numConds >= numCondsIn)
		{
			result = ERROR_INSUFFICIENT_BUFFER;
			goto CLEANUP;
		}
		// appPath must be a fully-qualified file name, and the file must
		// exist on the local machine.
		result = FwpmGetAppIdFromFileName0(appPath, appId);
		//BAIL_ON_ERROR(FwpmGetAppIdFromFileName0);
		conds[numConds].fieldKey = FWPM_CONDITION_ALE_APP_ID;
		conds[numConds].matchType = FWP_MATCH_EQUAL;
		conds[numConds].conditionValue.type = FWP_BYTE_BLOB_TYPE;
		conds[numConds].conditionValue.byteBlob = *appId;
		++numConds;
	}
	*numCondsOut = numConds;
CLEANUP:
	return result;
}
// wfpTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
int main()
{
	std::cout << "Adding a WFP filter to block all traffic to 8.8.8.8...\n";

	DWORD result = NO_ERROR;
	HANDLE engineHandle = NULL;
	UINT64 filterId = 0;

	// Define the remote IP address for 8.8.8.8
	SOCKADDR_IN remoteAddr;
	ZeroMemory(&remoteAddr, sizeof(remoteAddr));
	remoteAddr.sin_family = AF_INET;
	// Port is not needed to block all traffic, so set to 0
	remoteAddr.sin_port = 0;
	remoteAddr.sin_addr.s_addr = inet_addr("8.8.8.8");

	FWPM_FILTER_CONDITION0 conds[4];
	UINT32 numConds;
	FWP_BYTE_BLOB* appId = NULL;

	// Call InitFilterConditions with no protocol
	result = InitFilterConditions(
		NULL,
		NULL,
		(const SOCKADDR*)&remoteAddr,
		0,  // Specify 0 to not filter by protocol
		4,
		conds,
		&numConds,
		&appId
	);

	if (result != ERROR_SUCCESS)
	{
		printf("InitFilterConditions failed: 0x%08X\n", result);
		goto CLEANUP;
	}

	result = FwpmEngineOpen0(
		NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		NULL,
		&engineHandle
	);
	if (result != ERROR_SUCCESS)
	{
		printf("FwpmEngineOpen0 failed: 0x%08X\n", result);
		goto CLEANUP;
	}

	FWPM_FILTER0 filter;
	ZeroMemory(&filter, sizeof(filter));

	// Let the engine assign a key
	filter.displayData.name = const_cast<wchar_t*>(L"Block All Traffic to 8.8.8.8");
	filter.displayData.description = const_cast<wchar_t*>(L"Blocks all outbound connections to 8.8.8.8.");

	// Use a more general layer to catch all outbound connections
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;

	// The action is to block the traffic
	filter.action.type = FWP_ACTION_BLOCK;

	filter.numFilterConditions = numConds;
	filter.filterCondition = conds;

	result = FwpmFilterAdd0(
		engineHandle,
		&filter,
		NULL,
		&filterId
	);
	if (result != ERROR_SUCCESS)
	{
		printf("FwpmFilterAdd0 failed: 0x%08X\n", result);
		goto CLEANUP;
	}

	printf("Filter added successfully with ID: %llu\n", filterId);

	printf("Press any key to delete the filter and exit.\n");
	_getch();
	printf("Deleting filter with ID: %llu\n", filterId);
	result = FwpmFilterDeleteById0(engineHandle, filterId);
	if (result != ERROR_SUCCESS)
	{
		printf("FwpmFilterDeleteById0 failed: 0x%08X\n", result);
	}
	else
	{
		printf("Filter deleted successfully.\n");
	}

CLEANUP:
	if (engineHandle != NULL)
	{
		FwpmEngineClose0(engineHandle);
	}

	if (appId != NULL)
	{
		FwpmFreeMemory0((void**)&appId);
	}

	printf("Press any key to exit.\n");
	_getch();
	return result;
}

//int main()
//{
//	std::cout << "Adding a WFP filter...\n";
//
//	DWORD result = NO_ERROR;
//	HANDLE engineHandle = NULL;
//	UINT32 sessionFlags = FWPM_SESSION_FLAG_DYNAMIC;
//	UINT64 filterId = 0;
//
//	SOCKADDR_IN remoteAddr;
//	ZeroMemory(&remoteAddr, sizeof(remoteAddr));
//	remoteAddr.sin_family = AF_INET;
//	remoteAddr.sin_port = htons(5030); // Host to network short
//	remoteAddr.sin_addr.s_addr = inet_addr("10.11.12.13"); // Convert IP string to network address
//
//	FWPM_FILTER_CONDITION0 conds[4]; // Array to hold filter conditions
//	UINT32 numConds;
//	FWP_BYTE_BLOB* appId = NULL;
//
//	// Call InitFilterConditions to populate the filter conditions
//	result = InitFilterConditions(
//		NULL,
//		NULL,
//		(const SOCKADDR*)&remoteAddr,
//		IPPROTO_TCP,
//		4,
//		conds,
//		&numConds,
//		&appId
//	);
//
//	// Bail out if InitFilterConditions failed
//	if (result != ERROR_SUCCESS)
//	{
//		printf("InitFilterConditions failed: 0x%08X\n", result);
//		goto CLEANUP;
//	}
//
//	// Step 1: Open a session to the WFP engine
//	result = FwpmEngineOpen0(
//		NULL,
//		RPC_C_AUTHN_WINNT,
//		NULL,
//		NULL,
//		&engineHandle
//	);
//	if (result != ERROR_SUCCESS)
//	{
//		printf("FwpmEngineOpen0 failed: 0x%08X\n", result);
//		goto CLEANUP;
//	}
//
//	// Step 2: Define the filter structure
//	FWPM_FILTER0 filter;
//	ZeroMemory(&filter, sizeof(filter));
//
//	// The filter key must be a unique GUID. You can generate one or use a static one
//	// for this example.
//	//filter.filterKey = PROVIDER_KEY;
//	filter.displayData.name = const_cast<wchar_t*>(L"My IP Block Filter");
//	filter.displayData.description = const_cast<wchar_t*>(L"Blocks traffic to 10.11.12.13 on port 5030");
//
//	// Set the layer to the IPV4 transport layer
//	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
//	filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
//
//	// The action to take when the conditions are met: block the traffic
//	filter.action.type = FWP_ACTION_BLOCK;
//
//	// Set the filter's conditions
//	filter.numFilterConditions = numConds;
//	filter.filterCondition = conds;
//
//	// Step 3: Add the filter to the WFP engine
//	result = FwpmFilterAdd0(
//		engineHandle,
//		&filter,
//		NULL,
//		&filterId
//	);
//	if (result != ERROR_SUCCESS)
//	{
//		printf("FwpmFilterAdd0 failed: 0x%08X\n", result);
//		goto CLEANUP;
//	}
//
//	printf("Filter added successfully with ID: %llu\n", filterId);
//
//	Sleep(120 * 1000);
//
//CLEANUP:
//	// Close the session to the WFP engine
//	if (engineHandle != NULL)
//	{
//		FwpmEngineClose0(engineHandle);
//	}
//
//	// Free the application ID blob if it was allocated
//	if (appId != NULL)
//	{
//		FwpmFreeMemory0((void**)&appId);
//	}
//
//	printf("Press any key to exit.\n");
//	_getch();
//	return result;
//}

//int main()
//{
//    std::cout << "Hello World!\n";
//	SOCKADDR_IN remoteAddr;
//	ZeroMemory(&remoteAddr, sizeof(remoteAddr));
//	remoteAddr.sin_family = AF_INET;
//	remoteAddr.sin_port = htons(5030); // Host to network short
//	remoteAddr.sin_addr.s_addr = inet_addr("10.11.12.13"); // Convert IP string to network address
//
//	FWPM_FILTER_CONDITION0 conds[4]; // Array to hold filter conditions
//	UINT32 numConds;
//	FWP_BYTE_BLOB* appId = NULL;
//	DWORD result;
//
//	result = InitFilterConditions(
//		NULL, // No application path
//		NULL, // No local address
//		(const SOCKADDR*)&remoteAddr, // Remote address and port
//		IPPROTO_TCP, // TCP protocol
//		4,
//		conds,
//		&numConds,
//		&appId
//	);
//}