@echo off
REM Build engine_core như static lib cho kernel (x64). Chạy trên Windows.
REM Ra: target\x86_64-pc-windows-msvc\release\engine_core.lib (SnsDrv.vcxproj link).
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d "%~dp0"
"C:\Users\baosa\.cargo\bin\cargo.exe" rustc -p engine_core --release --features kernel ^
    --target x86_64-pc-windows-msvc --crate-type staticlib -- -C panic=abort
endlocal
