_MEMORY_BASIC_INFORMATION  struct
		BaseAddress			DWORD 	?
		AllocationBaseD 	DWORD 	?
		AllocationProtect 	DWORD 	?
		RegionSize 			DWORD 	?
		State 				DWORD 	?
		Protect 			DWORD 	?
		Type_ 				DWORD 	?
_MEMORY_BASIC_INFORMATION  ends


_IMAGE_DOS_HEADER struct
		e_magic    			WORD  	?				; Magic DOS signature
		e_cblp     			WORD  	?				; Bytes on last page of file
		e_cp       			WORD  	?				; Pages in file
		e_crlc     			WORD  	?				; Relocations
		e_cparhdr  			WORD  	?				; Size of header in paragraphs
		e_minalloc 			WORD  	?				; Minimun extra paragraphs needs
		e_maxalloc 			WORD  	?				; Maximun extra paragraphs needs
		e_ss       			WORD  	?				; intial(relative)SS value
		e_sp       			WORD  	?				; intial SP value
		e_csum     			WORD  	?				; Checksum
		e_ip       			WORD  	?				; intial IP value
		e_cs       			WORD  	?				; intial(relative)CS value
		e_lfarlc   			WORD  	?				; File Address of relocation table
		e_ovno     			WORD  	?				; Overlay number
		e_res   			WORD  	4 dup(?)		; Reserved words
		e_oemid    			WORD  	?				; OEM identifier(for e_oeminfo)
		e_oeminfo  			WORD  	?				; OEM informatione_oemid specific
		e_res2				WORD  	10 dup (?)		; Reserved words
		e_lfanew  			DWORD 	?				; Offset to start of PE header
_IMAGE_DOS_HEADER ends

_IMAGE_FILE_HEADER struct
		 Machine				WORD 	?	; CPU platform for program execution: 0X0: any platform, 0X14C: intel i386 and subsequent processors
		 NumberOfSections		WORD 	?	; The number of blocks in the PE file
		 TimeDateStamp			DWORD 	?	; Timestamp: The total number of seconds between the time the linker generated this file and 1969/12/31-16:00P:00
		 PointerToSymbolTable	DWORD 	?	; The offset position of the COFF symbol table. This field is only useful for COFF debugging information
		 NumberOfSymbols		DWORD 	?	; The number of symbols in the COFF symbol table. This value and the previous value are 0 in the release version of the program
		 SizeOfOptionalHeader	WORD 	?	; IMAGE_OPTIONAL_HEADER structure size (bytes): 32-bit default E0H, 64-bit default F0H (can be modified)
		 Characteristics		WORD 	?	; Describe file attributes, eg:
											; Single attribute (only 1bit is 1): #define IMAGE_FILE_DLL 0x2000 //File is a DLL.
											; Combined attributes (multiple bits are 1, single attribute or operation): 0X010F executable file
_IMAGE_FILE_HEADER ends


_IMAGE_DATA_DIRECTORY struct
      VirtualAddress 	DWORD 	?
      Size_           	DWORD 	?
_IMAGE_DATA_DIRECTORY ends

_IMAGE_OPTIONAL_HEADER struct
     Magic							WORD 					?			;                       //※Magic number (magic number), 0x0107: ROM image, 0x010B: 32-bit PE, 0X020B: 64-bit PE 
     MajorLinkerVersion				BYTE 					?			;          //Connector major version number
     MinorLinkerVersion				BYTE 					?			;          //Connector minor version number
     SizeOfCode						DWORD 					?			;                 //The total size of all code segments, note: it must be an integer multiple of FileAlignment, exists but is useless
     SizeOfInitializedData			DWORD 					?			;      //The size of the initialized data, note: it must be an integer multiple of FileAlignment, exists but is useless
     SizeOfUninitializedData		DWORD 					?				;    //The size of uninitialized data, note: it must be an integer multiple of FileAlignment, exists but is useless
     AddressOfEntryPoint			DWORD 					?				;        //The program entry address OEP, which is an RVA (Relative Virtual Address), usually falls in .textsection, this field is applicable to DLLs/EXEs.
     BaseOfCode						DWORD 					?			;                 //Code segment starting address (code base address), (the beginning of the code is not necessarily related to the program)
     BaseOfData						DWORD 					?			;                 //Data segment start address (data base address)
     ImageBase						DWORD 					?			;                  //Memory mirror base address (default loading starting address), default is 4000H
     SectionAlignment				DWORD 					?			;           //Memory alignment: Once mapped to memory, each section is guaranteed to start from a virtual address of "multiple of this value"
     FileAlignment					DWORD 					?			;              //File alignment: originally 200H, now 1000H
     MajorOperatingSystemVersion	WORD 					?				; //The required operating system major version number
     MinorOperatingSystemVersion	WORD 					?				; //Required operating system minor version number
     MajorImageVersion				WORD 					?			;           //Customize the main version number, use the parameter settings of the connector, eg:LINK /VERSION:2.0 myobj.obj
     MinorImageVersion				WORD 					?			;           //Customize the minor version number, use the parameter settings of the connector
     MajorSubsystemVersion			WORD 					?			;       //The required subsystem major version number, typical value 4.0 (Windows 4.0/that is, Windows 95)
     MinorSubsystemVersion			WORD 					?			;       //The required subsystem minor version number
     Win32VersionValue				DWORD 					?			;          //Always 0
     SizeOfImage					DWORD 					?				;                //The total image size of the PE file in memory, sizeof(ImageBuffer), a multiple of SectionAlignment
     SizeOfHeaders					DWORD 					?			;              //DOS header (64B) + PE mark (4B) + standard PE header (20B) + optional PE header + total size of section table, aligned according to the file (multiple of FileAlignment)
     CheckSum						DWORD 					?			;                   //PE file CRC checksum, to determine whether the file has been modified
     Subsystem						WORD 					?			;                   //Subsystem type used in the user interface
     DllCharacteristics				WORD 					?			;          //Always 0
     SizeOfStackReserve				DWORD 					?			;         //The reserved size of the default thread initialization stack
     SizeOfStackCommit				DWORD 					?			;          //The size of the thread stack actually submitted during initialization
     SizeOfHeapReserve				DWORD 					?			;          //The virtual memory size reserved for the initialized process heap by default
     SizeOfHeapCommit				DWORD 					?			;           //The actual submitted process heap size during initialization
     LoaderFlags					DWORD 					?			;                //Always 0
     NumberOfRvaAndSizes			DWORD 					?			;        //Number of directory items: always 0X00000010H(16)
     DataDirectory   				_IMAGE_DATA_DIRECTORY 16 dup({})		; //define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
_IMAGE_OPTIONAL_HEADER ends

_IMAGE_NT_HEADERS struct
		Signature			 DWORD 					?	; PE file signature 50 45 (PE)
		FileHeader		 	_IMAGE_FILE_HEADER 		{} 	; standard PE header
		OptionalHeader 		_IMAGE_OPTIONAL_HEADER	{}	; Optional Header
_IMAGE_NT_HEADERS ends

misc_ union 
		PhysicalAddress DWORD 	?
		VirtualSize 	DWORD 	?
misc_ ends

_IMAGE_SECTION_HEADER struct
		Name_  					BYTE  	8 dup(0) 
		misc 					misc_   {} 	
		VirtualAddress			DWORD 	?
		SizeOfRawData			DWORD   ?
		PointerToRawData		DWORD   ?
		PointerToRelocations	DWORD   ?
		PointerToLinenumbers	DWORD   ?
		NumberOfRelocations		WORD    ?
		NumberOfLinenumbers		WORD    ?
		Characteristics			DWORD   ?
_IMAGE_SECTION_HEADER ends

PIMAGE_SECTION_HEADER 	typedef DWORD
PIMAGE_NT_HEADERS 		typedef DWORD
PIMAGE_SECTION_HEADER 	typedef DWORD

_LOADED_IMAGE struct
	ModuleName			DWORD                 	?
	hFile				DWORD                   ?
	MappedAddress		DWORD                   ?
	FileHeader			PIMAGE_NT_HEADERS   	?
	LastRvaSection		PIMAGE_SECTION_HEADER   ?
	NumberOfSections	DWORD                   ?
	Sections			PIMAGE_SECTION_HEADER   ?
	Characteristics		DWORD                   ?
	fSystemImage		BYTE                    ?
	fDOSImage			BYTE                    ?
	fReadOnly			BYTE                    ?
	Version				BYTE                    ?
	Links				DWORD              		?
	Links_				DWORD					?
	SizeOfImage			DWORD                   ?
_LOADED_IMAGE ends

_SECURITY_ATTRIBUTES struct
	nLength					DWORD  	?
	lpSecurityDescriptor	DWORD 	?
	bInheritHandle			BYTE   	?
_SECURITY_ATTRIBUTES ends