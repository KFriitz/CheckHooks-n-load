@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp checkHooks-n-load.cpp /link /OUT:checkHooks-n-load.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
::cl.exe /nologo /Od /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /OUT:Inject.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj
