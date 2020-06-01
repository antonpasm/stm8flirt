rem TODO
set arc=obj_mm_hz\STM8L15x_StdPeriph_Driver_mm_hz.a
set pat=obj_mm_hz\STM8L15x_StdPeriph_Driver_mm_hz.pat

set idatool_sigmake="D:\flair68\bin\win\sigmake.exe"


python ..\stm8sig.py %arc%

::%idatool_sigmake% -d "-nIAR Data" data.pat ..\Output\data.sig