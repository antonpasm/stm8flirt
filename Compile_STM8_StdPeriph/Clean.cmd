@set obj=obj_*
@for /d %%d in (%obj%) do rmdir /S /Q %%~d
