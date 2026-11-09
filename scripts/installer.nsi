; Установщик WDTT для Windows (NSIS 3, Unicode).
;
; Собирается в CI (release.yml):
;   makensis /DVERSION=2.1.6.1 /DSRCDIR=<папка сборки> /DOUTFILE=<setup.exe> scripts\installer.nsi
; В SRCDIR лежат wdtt.exe, cli\wdtt.exe и install.ps1.
;
; Регистрацию (задача планировщика «WDTT» с наивысшими правами — запуск без
; UAC, команда `wdtt` в PATH, ярлыки, автозапуск) делает install.ps1 -InPlace:
; та же логика, что при установке скриптом, в одном месте.

Unicode true
ManifestDPIAware true
SetCompressor /SOLID lzma

!ifndef VERSION
  !define VERSION "0.0.0.0"
!endif
!ifndef SRCDIR
  !define SRCDIR "..\build\bin"
!endif
!ifndef OUTFILE
  !define OUTFILE "wdtt-setup-windows-amd64.exe"
!endif

!define APPNAME "WDTT"
!define PUBLISHER "WDTT (avanturist888 fork)"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\WDTT"

Name "${APPNAME} ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\WDTT"
RequestExecutionLevel admin
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${VERSION}"
VIAddVersionKey /LANG=0 "ProductName" "${APPNAME}"
VIAddVersionKey /LANG=0 "FileDescription" "WDTT installer"
VIAddVersionKey /LANG=0 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=0 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=0 "CompanyName" "${PUBLISHER}"
VIAddVersionKey /LANG=0 "LegalCopyright" "GPL-3.0"

!include "MUI2.nsh"
!include "x64.nsh"

!define MUI_ICON "..\build\windows\icon.ico"
!define MUI_UNICON "..\build\windows\icon.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchApp
!define MUI_FINISHPAGE_RUN_TEXT "Запустить WDTT"

!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Russian"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "WDTT работает только на 64-битной Windows."
    Abort
  ${EndIf}
  SetRegView 64
FunctionEnd

Function un.onInit
  SetRegView 64
FunctionEnd

; Закрыть запущенный WDTT: занятый exe не перезаписать.
!macro StopApp
  DetailPrint "Останавливаю WDTT, если запущен…"
  nsExec::Exec 'taskkill /F /IM wdtt.exe /T'
  Pop $0
  Sleep 1500
!macroend

Function LaunchApp
  ; Через задачу планировщика — с правами, без запроса UAC.
  nsExec::Exec 'schtasks /run /tn WDTT'
  Pop $0
FunctionEnd

Section "WDTT" SecMain
  SectionIn RO
  !insertmacro StopApp

  SetOutPath "$INSTDIR"
  File "${SRCDIR}\wdtt.exe"
  File "${SRCDIR}\install.ps1"
  SetOutPath "$INSTDIR\cli"
  File "${SRCDIR}\cli\wdtt.exe"
  SetOutPath "$INSTDIR"

  DetailPrint "Регистрирую запуск без UAC, команду wdtt и автозапуск…"
  nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\install.ps1" -InPlace -InstallDir "$INSTDIR" -AutoStart'
  Pop $0
  ${If} $0 != "0"
    MessageBox MB_ICONEXCLAMATION "Регистрация завершилась с кодом $0. Подробности — в %TEMP%\wdtt-install.log."
  ${EndIf}

  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayIcon" "$INSTDIR\wdtt.exe"
  WriteRegStr HKLM "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTKEY}" "URLInfoAbout" "https://github.com/avanturist888/proxy-turn-vk-windows"
  WriteRegStr HKLM "${UNINSTKEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINSTKEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  !insertmacro StopApp
  DetailPrint "Убираю задачу, ярлыки, PATH и автозапуск…"
  nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\install.ps1" -Uninstall -KeepFiles -InstallDir "$INSTDIR"'
  Pop $0

  Delete "$INSTDIR\cli\wdtt.exe"
  Delete "$INSTDIR\cli\wdtt.exe.old-*"
  RMDir "$INSTDIR\cli"
  Delete "$INSTDIR\wdtt.exe"
  Delete "$INSTDIR\wdtt.exe.old-*"
  Delete "$INSTDIR\install.ps1"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINSTKEY}"
  ; Настройки и профили (%APPDATA%\wdtt) остаются — переустановка их подхватит.
SectionEnd
