#include "PEImage.h"
#include "exceptions.h"
#include <Windows.h>
#include "DumpPE.h"

using namespace std;

shared_ptr<std::string> PEImage::getImage()
{
	return m_image;
}

DWORD PEImage::getImageSize()
{
	return m_imageSize;
}

PEImage::PEImage()
{
	// Intentionally left empty.
}

std::shared_ptr<PEImage> PEImage::fromMemory(ULONG_PTR imageBase)
{
	ULONG bytesRead = 0;
	IMAGE_DOS_HEADER dosHeader;

	// Verify DOS magic
	ULONG rc = ReadMemory(imageBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead);
	
	if (bytesRead != sizeof(IMAGE_DOS_HEADER) || memcmp(&dosHeader.e_magic, &DOS_SIGNATURE, sizeof(DOS_SIGNATURE))) {
		dprintf("Address %p does not contain the beginning of a valid PE image (DOS header signature check failed)\n", imageBase);
		throw BadPEException();
	}
	dprintf("DOS magic found\n");
	
	// Verify PE magic
	IMAGE_NT_HEADERS ntHeaders;
	rc = ReadMemory(imageBase+dosHeader.e_lfanew, &ntHeaders, sizeof(IMAGE_NT_HEADERS), &bytesRead);
	if (bytesRead != sizeof(IMAGE_NT_HEADERS) || memcmp(&ntHeaders.Signature, &PE_SIGNATURE, sizeof(PE_SIGNATURE))) {
		dprintf("Address %p does not contain the beginning of a valid PE image (NT header signature check failed)\n", imageBase+dosHeader.e_lfanew);
		throw BadPEException();
	}
	dprintf("PE magic found\n");

	
	std::shared_ptr<PEImage> peImage(new PEImage());
	
	// Get the image size
	peImage->m_imageSize = ntHeaders.OptionalHeader.SizeOfImage;
	dprintf("SizeOfImage is %u\n", peImage->m_imageSize);
	
	// Read the whole image into memory.
	std::shared_ptr<BYTE> rawBuffer(new BYTE[peImage->m_imageSize]);
	ReadMemory(imageBase, rawBuffer.get(), peImage->m_imageSize, &bytesRead);

	peImage->m_image.reset(new string((char*)rawBuffer.get(), peImage->m_imageSize));
	if (bytesRead != peImage->m_imageSize) {
		dprintf("ERROR: PE size is %d but only %d bytes were found", peImage->m_imageSize, bytesRead);
		throw ReadMemoryException();
	}
	
	return peImage;
}
LONG PEImage::getNTHeaderOffset() 
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)m_image->c_str();
	return dosHeader->e_lfanew;
}

DWORD PEImage::getSectionAlignment()
{
	std::string ntHeaders = getNTHeaders();
	return ((PIMAGE_NT_HEADERS)ntHeaders.c_str())->OptionalHeader.SectionAlignment;
}

DWORD PEImage::getFileAlignment()
{
	std::string ntHeaders = getNTHeaders();
	return ((PIMAGE_NT_HEADERS)ntHeaders.c_str())->OptionalHeader.FileAlignment;
}
std::string PEImage::getDOSStub()
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)m_image->c_str();
	return std::string((char*)dosHeader, dosHeader->e_lfanew);
}
std::string PEImage::getNTHeaders()
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)m_image->c_str();	
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)dosHeader + dosHeader->e_lfanew);
	return std::string((char*)ntHeaders, sizeof(IMAGE_NT_HEADERS));
}
std::string PEImage::getSectionHeaders()
{
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(m_image->c_str() + getNTHeaderOffset());
	PIMAGE_SECTION_HEADER sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
	uint32_t size = ntHeaders->FileHeader.NumberOfSections;
	return std::string((char*)sectionHeaders, ntHeaders->FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER));
	
}

std::string PEImage::getSections()
{
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(m_image->c_str() + getNTHeaderOffset());
	std::string s;
	PIMAGE_SECTION_HEADER currentSectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		LPVOID sectionStartInMemory = (LPVOID)(m_image->c_str() + currentSectionHeader->VirtualAddress);
		s += std::string((char*)sectionStartInMemory, currentSectionHeader->SizeOfRawData);
		currentSectionHeader++;
	}
	return s;
}