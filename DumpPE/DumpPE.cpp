#include <Windows.h>
#include "exceptions.h"
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <memory>
#include "DumpPE.h"
#include "PEImage.h"

using namespace std;
void fixAlignment(ostream& outputStream, DWORD alignment);
//ExtensionApis = {0};
/***********************************************************
 * Global Variable Needed For Functions
 ***********************************************************/              
WINDBG_EXTENSION_APIS ExtensionApis = {0};

/***********************************************************
 * Global Variable Needed For Versioning
 ***********************************************************/              
EXT_API_VERSION g_ExtApiVersion = {
         5 ,
         5 ,
         EXT_API_VERSION_NUMBER64 ,
         0
     } ;

/***********************************************************
 * ExtensionApiVersion
 *
 * Purpose: WINDBG will call this function to get the version
 *          of the API
 *
 *  Parameters:
 *     Void
 *
 *  Return Values:
 *     Pointer to a EXT_API_VERSION structure.
 *
 ***********************************************************/              
LPEXT_API_VERSION WDBGAPI ExtensionApiVersion (void)
{
    return &g_ExtApiVersion;
}

/***********************************************************
 * WinDbgExtensionDllInit
 *
 * Purpose: WINDBG will call this function to initialize
 *          the API
 *
 *  Parameters:
 *     Pointer to the API functions, Major Version, Minor Version
 *
 *  Return Values:
 *     Nothing
 *
 ***********************************************************/              

static vector<string> splitArgs(string& cArgs) 
{
	istringstream iss(cArgs);
	vector<string> argsVector;
	copy(istream_iterator<string>(iss), istream_iterator<string>(), back_inserter<vector<string>>(argsVector));
	
	return argsVector;
}

VOID WDBGAPI WinDbgExtensionDllInit (PWINDBG_EXTENSION_APIS
           lpExtensionApis, USHORT usMajorVersion, 
           USHORT usMinorVersion)
{
     ExtensionApis = *lpExtensionApis;
}

DECLARE_API(dump_raw)
{
	ULONG64 imageBase;
	string cArgs(args);
	vector<string> argsVector = splitArgs(cArgs);

	if (argsVector.size() != 2) {
		dprintf("Usage: !dumppe.dump <address> <output file>\n");
		return;
	}
	imageBase = GetExpression(argsVector[0].c_str());
	try {
		shared_ptr<PEImage> peImage = PEImage::fromMemory(imageBase);
		ofstream outputStream(argsVector[1], ofstream::binary);
		outputStream.write((char*)peImage->getImage()->c_str(), peImage->getImageSize());
		outputStream.close();
	}
	catch (...) 
	{
		dprintf("An error has occurred\n");
		return;
	}
}
DECLARE_API(ssdt)
{
	ULONG64 imageBase;
	string cArgs(args);
	vector<string> argsVector = splitArgs(cArgs);

	if (argsVector.size() != 1) {
		dprintf("Usage: !ssdt <length>");
		return;
	}

	ULONG64 length = GetExpression(argsVector[0].c_str());
	ULONG64 ssdtAddress = GetExpression("nt!KiServiceTable");

	for (ULONG_PTR i = 0; i < length; i += 4)
	{
		char symbolName[1024];
		DWORD offset;
		DWORD bytesRead = 0;
		ReadMemory(ssdtAddress + i, &offset, 4, &bytesRead);
		
		ULONG64 displacement = 0; 
		GetSymbol(ssdtAddress + (offset>>4), symbolName, &displacement);
		if (displacement != 0)
		{
			symbolName[0] = '\0';
		}
		else {
			dprintf("%p %p %s\n", ssdtAddress + offset, ssdtAddress + (offset>>4), symbolName);
		}
	}
}

DECLARE_API(dump_disk)
{
	ULONG64 imageBase;
	string cArgs(args);
	vector<string> argsVector = splitArgs(cArgs);
	if (argsVector.size() != 2) {
		dprintf("Usage: !dumppe.dump <address> <output file>\n");
		return;
	}
	imageBase = GetExpression(argsVector[0].c_str());
	try {
		shared_ptr<PEImage> peImage = PEImage::fromMemory(imageBase);
		
		// Write DOS header
		dprintf("Dumping DOS stub...\n");
		ofstream outputStream(argsVector[1], ofstream::binary);
		outputStream<<peImage->getDOSStub();
		
		dprintf("Dumping NT headers...\n");
		//Write NT headers
		outputStream<<peImage->getNTHeaders();
		dprintf("Dumping section headers...\n");
		outputStream<<peImage->getSectionHeaders();
		dprintf("Fixing file alignment...\n");
		fixAlignment(outputStream, peImage->getFileAlignment());
		dprintf("Dumping sections...\n");
		outputStream<<peImage->getSections();
	}
	catch (...) 
	{
		dprintf("An error has occurred\n");
		return;
	}
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		return TRUE;
	}
	
}
void fixAlignment(ostream& outputStream, DWORD alignment)
{
	streamoff currentPos = outputStream.tellp();
	streamoff numOfBytesToWrite = 0;
	if (currentPos < alignment) 
	{
		numOfBytesToWrite = alignment - currentPos;
	}
	else { 
		numOfBytesToWrite = alignment - (currentPos % alignment);
	}
	dprintf("Padding with %u null bytes\n", numOfBytesToWrite);
	outputStream<<string(numOfBytesToWrite, '\0');
}