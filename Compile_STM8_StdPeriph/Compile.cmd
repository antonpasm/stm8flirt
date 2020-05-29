@set icc="C:\Program Files (x86)\IAR Systems\Embedded Workbench 6.5\stm8\bin\iccstm8.exe"
@set iarc="C:\Program Files (x86)\IAR Systems\Embedded Workbench 8.3\stm8\bin\iarchive.exe"
@set def=-D STM8L15X_HD
@set mod=--code_model medium --data_model medium
@set stm8lib=STM8L15x_StdPeriph_Driver
@set obj=obj

@mkdir %obj%
@for %%f in (%stm8lib%\src\*.c) do %icc% %%~f -e -Ohz %mod% %def% -o %obj%\ -I %stm8lib%\inc -I .\

@setlocal EnableDelayedExpansion
@pushd %cd%
@cd %obj%
@for %%f in (*.o) do @set list=!list! %%~f
%iarc% --create %stm8lib%.a %list%
@popd
