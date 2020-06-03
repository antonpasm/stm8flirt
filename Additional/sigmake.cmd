set idatool_sigmake="D:\flair68\bin\win\sigmake.exe"

python ..\stm8sig.py codefix\cstartup_fix.txt
python ..\stm8sig.py codefix\cexit_fix.txt

%idatool_sigmake% -d "-nIAR some additions" data\data.pat codefix\cstartup_fix.pat codefix\cexit_fix.pat ..\Output\additions.sig