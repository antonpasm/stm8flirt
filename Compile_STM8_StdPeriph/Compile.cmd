call :compile medium medium hz mm_hz
:call :compile small small hz ss_hz

@goto :eof

:compile
@set icc="C:\Program Files (x86)\IAR Systems\Embedded Workbench 6.5\stm8\bin\iccstm8.exe"
@set iarc="C:\Program Files (x86)\IAR Systems\Embedded Workbench 8.3\stm8\bin\iarchive.exe"
@set def=-D STM8L15X_HD
@set cmod=%1
@set dmod=%2
@set opt=%3
@set suff=%4
@set stm8lib=STM8L15x_StdPeriph_Driver
@set obj=obj_%suff%

@mkdir %obj% 2>NUL
@for %%f in (%stm8lib%\src\*.c) do %icc% %%~f -e -O%opt% --code_model %cmod% --data_model %dmod% %def% -o %obj%\ -I %stm8lib%\inc -I .\

@setlocal EnableDelayedExpansion
@pushd %cd%
@cd %obj%
@for %%f in (*.o) do @set list=!list! %%~f
%iarc% --create %stm8lib%_%suff%.a %list%
@popd
@exit /b
