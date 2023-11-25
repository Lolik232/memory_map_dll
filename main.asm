.386 ; Тип процессора
.model flat, stdcall ; Модель памяти и стиль вызова подпрограмм
option casemap: none ; Чувствительность к регистру
; --- Подключение файлов с кодом, макросами, константами, прототипами функций и т.д.
include windows.inc
include kernel32.inc
include user32.inc
include msvcrt.inc
include psapi.inc
include imagehlp.inc

include win-api-structs.inc
include winapi-consts.inc

; --- Подключаемые библиотеки ---
includelib user32.lib
includelib kernel32.lib
includelib msvcrt.lib
includelib psapi.lib
includelib imagehlp.lib


.data?
	mem_type_ptr			DWORD						?			
	mem_protect_ptr			DWORD						?	
	hProcess_				DWORD 						?
	
.data
	mbi 					_MEMORY_BASIC_INFORMATION 	{}
	mbi_section				_MEMORY_BASIC_INFORMATION 	{}
	
	fmt_memory 				db 							"%15x |", "%5s | %4s |", 9, " %10x", 10, 13, 0
	fmt_file_at_addr 		db 							"file %10x |", "%5s | %4s |", 9, " %s", 10, 13, 0
	fmt_sections			db							"sections: %x", 10,13,0
	fmt_header 				db 							"sect %10x |","%5s | %4s | %10s", 10, 13, 0
	fmt_error				db 							"error %d", 10, 13, 0
	fmt_table_header		db							"      base addr ", "|  ACC ","|  TYPE |", 9,9, "  SIZE|" , 10, 13, "------------------------------------------------", 10, 13, 0
	
	dos_header 				_IMAGE_DOS_HEADER			{}
	nt_headers				_IMAGE_NT_HEADERS			{}
	image_header			_IMAGE_SECTION_HEADER		{}
	
	loaded_image 			_LOADED_IMAGE				{}
	
	nameBuffer 				db 255 dup(0)
	
		
	mem_type_image			db 							"-img-", 0
	mem_type_mapped			db 							"-map-", 0
	mem_type_private		db 							"-prv-", 0

	mem_protect_rw			db 							"-rw--", 0
	mem_protect_r			db 							"-r---", 0
	mem_protect_e			db 							"e----", 0
	mem_protect_er			db 							"er---", 0
	mem_protect_NO			db 							"-----", 0
	
	current_address dd 0
.code

DllEntry proc hInstDLL:HINSTANCE, reason:DWORD, reserved1:DWORD
           mov  eax, 1
           ret
DllEntry Endp

print_table PROTO

check_pe_image proc uses ebx image_base_addr : dword
	LOCAL len 			: DWORD
	
	
	invoke ReadProcessMemory, hProcess_ , \
							  image_base_addr, \
							  offset dos_header,\
							  sizeof _IMAGE_DOS_HEADER,\
							  addr len
	
	.IF ax == 0
		ret
	.ENDIF
	
	; МАГИЧЕСКАЯ КОНСТАНТА PE файлов (MZ), но в памяти записана наоборот
	.IF dos_header.e_magic != "ZM"
		xor eax, eax
		ret
	.ENDIF
	
	; смещаемся к PE Header структуре
	; base_addr + lfanew - адрес начала заголовка
	mov eax, image_base_addr
	add eax, dos_header.e_lfanew
	mov image_base_addr, eax
	
	; читаем PE header информацию
	invoke ReadProcessMemory, hProcess_, \
							  image_base_addr, \
							  offset nt_headers,\
							  sizeof _IMAGE_NT_HEADERS,\
							  addr len
	
	; сигнатура должна быть PE но в памяти записана наоборот
	.IF nt_headers.Signature != "EP"  
		xor eax, eax
		ret
	.ENDIF 
	
	mov eax, 1
	
	ret
check_pe_image endp

get_access proc uses eax image_base_addr : dword
	invoke VirtualQuery, image_base_addr, \
						 offset mbi_section, \
						 sizeof _MEMORY_BASIC_INFORMATION
	
	.IF mbi_section.Protect == PAGE_READWRITE
		mov mem_protect_ptr, offset mem_protect_rw
	.ELSEIF mbi_section.Protect == PAGE_READONLY
		mov mem_protect_ptr, offset mem_protect_r
	.ELSEIF mbi_section.Protect == PAGE_EXECUTE
		mov mem_protect_ptr, offset mem_protect_e
	.ELSEIF mbi_section.Protect == PAGE_EXECUTE_READ
		mov mem_protect_ptr, offset mem_protect_er
	.ELSE
		mov mem_protect_ptr, offset mem_protect_NO
	.ENDIF
	
	.IF mbi_section.Type_ == MEM_IMAGE
		mov mem_type_ptr, offset mem_type_image
	.ELSEIF mbi_section.Type_ == MEM_MAPPED
		mov mem_type_ptr, offset mem_type_mapped
	.ELSE
		mov mem_type_ptr, offset mem_type_private
	.ENDIF
	
	ret
get_access endp

main proc
	invoke print_table

	push 0
	call ExitProcess
main endp

print_table proc
	LOCAL len : dword
	invoke crt_printf, offset fmt_table_header


	call GetCurrentProcess
	mov hProcess_, eax

	; получаем информацию о текущем участке памяти
	invoke VirtualQuery, current_address, \
						 offset mbi, \
						 sizeof _MEMORY_BASIC_INFORMATION
	.while (eax != 0 )
		; проверяем, является ли текущий участок - PE файлом
		invoke check_pe_image, mbi.BaseAddress
		
		; если является - выводим информацию о нём
		.IF ax == 1
			; получаем имя файла
			invoke GetMappedFileNameA, hProcess_, 		\
									   mbi.BaseAddress, \
									   addr nameBuffer, \
									   sizeof nameBuffer \
	
			.IF eax == 0
				mov nameBuffer[0], 0
			.ELSE
				; получаеим права доступа к файлу
				invoke get_access, mbi.BaseAddress
			.ENDIF
				
			
			invoke crt_printf, offset fmt_file_at_addr, \
							   mbi.BaseAddress, \
							   mem_protect_ptr, \
							   mem_type_ptr,\
							   addr nameBuffer[0]
			
			; адрес начала секций в PE файле
			xor ebx, ebx
			mov ebx, dos_header.e_lfanew
			add ebx, mbi.BaseAddress
			add ebx, sizeof _IMAGE_NT_HEADERS
		
			push ecx
			movsx ecx, nt_headers.FileHeader.NumberOfSections
			
			; выводим секции PE файла
			print_sections:
				push ecx
				push ebx
				
				; читаем текущую секцию -> структура IMAGE SECTION HEADER
				invoke ReadProcessMemory, hProcess_, \
										  ebx, \
										  offset image_header, \
										  sizeof _IMAGE_SECTION_HEADER,\
										  addr len
	
				mov ebx, mbi.BaseAddress
				add ebx, image_header.VirtualAddress
			
				; получаем права доступа
				invoke get_access, ebx
			
				invoke crt_printf, offset fmt_header,\
								   ebx, mem_protect_ptr,\
								   mem_type_ptr, \
								   addr image_header.Name_
				
				pop ebx
				pop ecx
				
				add ebx, sizeof image_header
				
				; сдвигаем указатель на начало следующей секции
				mov eax, mbi.BaseAddress
				add eax, image_header.VirtualAddress
				add eax, mbi.RegionSize
				mov current_address, eax
				
			loop print_sections
			pop ecx
			
		.ELSE
			invoke get_access, mbi.BaseAddress
			invoke crt_printf, offset fmt_memory, \
							   mbi.BaseAddress, \
							   mem_protect_ptr, \
							   mem_type_ptr, mbi.RegionSize
		
			mov ebx, mbi.RegionSize
			add current_address, ebx	
		.ENDIF
		
		invoke VirtualQuery, current_address, \
							 offset mbi, \
							 sizeof _MEMORY_BASIC_INFORMATION
	.endw
	
	ret
print_table endp

END DllEntry