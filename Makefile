# define LIB and INCLUDE path for assembly libs in Windows

mdll:
	if exist del out /q
	if not exist out mkdir out
	ml /c /coff /I $(INCLUDE) /Fo .\out\memmap.obj main.asm
	Link /subsystem:windows /LIBPATH:$(LIB) /DLL /DEF:main.def .\out\memmap.obj /OUT:./out/memmap.dll