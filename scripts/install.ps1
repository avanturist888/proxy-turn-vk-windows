<#
.SYNOPSIS
  Установка WDTT: запуск без запроса UAC и консольная команда `wdtt`.

.DESCRIPTION
  Туннелю нужны права администратора (адаптер, маршруты, DNS). Вместо
  запроса UAC при каждом запуске скрипт один раз:
    - копирует wdtt.exe в Program Files (обычный процесс не может его
      подменить — иначе задача с наивысшими правами стала бы обходом UAC);
    - регистрирует задачу планировщика «WDTT» с наивысшими правами: обычный
      запуск wdtt.exe передаёт ей работу и UAC не спрашивает;
    - кладёт консольную утилиту в <папка>\cli\wdtt.exe и добавляет эту папку
      в PATH пользователя: `wdtt status`, `wdtt switch`, `wdtt check` …;
    - создаёт ярлыки в меню «Пуск» и на рабочем столе.

  Повторный запуск обновляет установку (в том числе пока приложение работает:
  занятый файл переименовывается и заменяется, новая версия начнёт работать
  после перезапуска приложения или с ключом -Switch).

.PARAMETER Source
  Папка сборки: wdtt.exe и cli\wdtt.exe (по умолчанию ..\build\bin).

.PARAMETER Switch
  После установки остановить запущенный WDTT, запустить установленный и
  подключиться к последнему серверу. Связь пропадёт на время переподключения.

.PARAMETER ReplaceOld
  Путь к прежней копии wdtt.exe (например, на рабочем столе): она уносится в
  %LOCALAPPDATA%\wdtt\old, а на её месте появляется ярлык.

.PARAMETER AutoStart
  Включить автозапуск после входа в Windows с подключением к последнему
  серверу (wdtt.exe --connect).

.PARAMETER Uninstall
  Удалить задачу, ярлыки, запись в PATH и папку установки.

.PARAMETER InPlace
  Файлы уже лежат в InstallDir (их положил установщик setup.exe): не
  копировать, только зарегистрировать задачу, PATH, ярлыки, автозапуск.

.PARAMETER KeepFiles
  С -Uninstall: папку установки не удалять (это сделает деинсталлятор).

.PARAMETER Launch
  После установки запустить приложение (без ожидания подключения).
#>
param(
    [string]$Source = (Join-Path $PSScriptRoot '..\build\bin'),
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'WDTT'),
    [switch]$Switch,
    [string]$ReplaceOld,
    [switch]$AutoStart,
    [switch]$Uninstall,
    [switch]$InPlace,
    [switch]$KeepFiles,
    [switch]$Launch
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    # Перезапуск себя с правами администратора (один запрос UAC).
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [System.Management.Automation.SwitchParameter]) {
            if ($kv.Value.IsPresent) { $argList += "-$($kv.Key)" }
        } else {
            $argList += "-$($kv.Key)"; $argList += "`"$($kv.Value)`""
        }
    }
    $p = Start-Process powershell.exe -Verb RunAs -ArgumentList $argList -Wait -PassThru
    exit $p.ExitCode
}

$taskName = 'WDTT'
$cliDir = Join-Path $InstallDir 'cli'
$guiExe = Join-Path $InstallDir 'wdtt.exe'
$cliExe = Join-Path $cliDir 'wdtt.exe'
$startMenuLnk = Join-Path ([Environment]::GetFolderPath('Programs')) 'WDTT.lnk'
$desktopLnk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'WDTT.lnk'
$logPath = Join-Path $env:TEMP 'wdtt-install.log'
Start-Transcript -Path $logPath -Force | Out-Null

function Set-UserPath([string]$dir, [bool]$present) {
    $cur = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @($cur -split ';' | Where-Object { $_ -and ($_.TrimEnd('\') -ne $dir.TrimEnd('\')) })
    if ($present) { $parts += $dir }
    [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')
}

function New-Shortcut([string]$path, [string]$target) {
    $sh = New-Object -ComObject WScript.Shell
    $lnk = $sh.CreateShortcut($path)
    $lnk.TargetPath = $target
    $lnk.WorkingDirectory = Split-Path $target
    $lnk.IconLocation = "$target,0"
    $lnk.Description = 'WDTT'
    $lnk.Save()
}

# Копирует файл, даже если цель сейчас запущена: занятый exe нельзя
# перезаписать, но можно переименовать.
function Install-File([string]$src, [string]$dst) {
    if (Test-Path $dst) {
        try { Remove-Item $dst -Force }
        catch { Rename-Item $dst ("{0}.old-{1}" -f (Split-Path $dst -Leaf), (Get-Date -Format 'yyyyMMdd-HHmmss')) -Force }
    }
    Copy-Item $src $dst -Force
}

# Флаг совместимости «Запускать от имени администратора» больше не нужен:
# с ним каждый запуск снова спрашивал бы UAC.
function Remove-RunAsAdminFlags {
    $key = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
    if (-not (Test-Path $key)) { return }
    $props = (Get-ItemProperty $key).PSObject.Properties | Where-Object { $_.Name -like '*\wdtt.exe' }
    foreach ($p in $props) {
        $rest = (($p.Value -split ' ') | Where-Object { $_ -and $_ -ne 'RUNASADMIN' -and $_ -ne '~' })
        if ($rest) { Set-ItemProperty $key -Name $p.Name -Value ('~ ' + ($rest -join ' ')) }
        else { Remove-ItemProperty $key -Name $p.Name }
        Write-Host "Снят флаг «от имени администратора»: $($p.Name)"
    }
}

function Get-OtherWdtt {
    Get-CimInstance Win32_Process -Filter "Name='wdtt.exe'" |
        Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -notlike "$cliDir\*") }
}

if ($Uninstall) {
    Get-OtherWdtt | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Set-UserPath $cliDir $false
    Remove-Item $startMenuLnk, $desktopLnk -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name WDTT -ErrorAction SilentlyContinue
    if (-not $KeepFiles) { Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host 'WDTT удалён (настройки и профили в %APPDATA%\wdtt оставлены).'
    Stop-Transcript | Out-Null
    exit 0
}

# 1. Файлы.
if ($InPlace) {
    foreach ($f in $guiExe, $cliExe) {
        if (-not (Test-Path $f)) { throw "Нет файла установки: $f" }
    }
} else {
    $srcGui = Join-Path $Source 'wdtt.exe'
    $srcCli = Join-Path $Source 'cli\wdtt.exe'
    foreach ($f in $srcGui, $srcCli) {
        if (-not (Test-Path $f)) { throw "Нет файла сборки: $f" }
    }
    New-Item -ItemType Directory -Force -Path $cliDir | Out-Null
    Get-ChildItem $InstallDir, $cliDir -Filter '*.old-*' -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
    Install-File $srcGui $guiExe
    Install-File $srcCli $cliExe
}
Write-Host "Установлено в $InstallDir"

# 2. Задача планировщика: запуск с наивысшими правами без UAC, в сеансе
#    пользователя (окно, трей, капча). Без ограничения времени работы
#    (по умолчанию задачу снимают через 72 часа), не останавливать на
#    батарее, обычный приоритет (по умолчанию — ниже обычного).
$action = New-ScheduledTaskAction -Execute $guiExe -WorkingDirectory $InstallDir
$principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -Priority 4 -StartWhenAvailable
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings `
    -Description 'WDTT: запуск туннеля с правами администратора без запроса UAC' -Force | Out-Null
Write-Host "Задача планировщика «$taskName» зарегистрирована"

# 3. Консольная команда.
Set-UserPath $cliDir $true
Write-Host "Команда wdtt: $cliExe (в PATH; работает в новых окнах консоли)"

# 4. Ярлыки и старые копии.
New-Shortcut $startMenuLnk $guiExe
if ($ReplaceOld -and (Test-Path $ReplaceOld) -and ((Resolve-Path $ReplaceOld).Path -ne $guiExe)) {
    $oldDir = Join-Path $env:LOCALAPPDATA 'wdtt\old'
    New-Item -ItemType Directory -Force -Path $oldDir | Out-Null
    $dest = Join-Path $oldDir ("wdtt-{0}.exe" -f (Get-Date (Get-Item $ReplaceOld).LastWriteTime -Format 'yyyy-MM-dd'))
    Move-Item $ReplaceOld $dest -Force
    Write-Host "Прежняя копия перенесена: $dest"
}
New-Shortcut $desktopLnk $guiExe
Remove-RunAsAdminFlags

# Автозапуск (если включён) — на установленную копию.
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if ($AutoStart -or (Get-ItemProperty $runKey -ErrorAction SilentlyContinue).WDTT) {
    if (-not (Test-Path $runKey)) { New-Item -Path $runKey -Force | Out-Null }  # на чистом профиле ключа может не быть
    Set-ItemProperty $runKey -Name WDTT -Value "`"$guiExe`" --connect"
    Write-Host 'Автозапуск: установленная копия, с подключением'
}

# 5. Переход на установленную копию.
if ($Switch) {
    $others = @(Get-OtherWdtt | Where-Object { $_.ExecutablePath -ne $guiExe })
    $running = @(Get-OtherWdtt | Where-Object { $_.ExecutablePath -eq $guiExe })
    foreach ($p in $others + $running) {
        Write-Host "Останавливаю $($p.ExecutablePath) (PID $($p.ProcessId))"
        Stop-Process -Id $p.ProcessId -Force
    }
    Start-Sleep -Seconds 3
    $cfg = Join-Path $env:APPDATA 'wdtt'
    New-Item -ItemType Directory -Force -Path $cfg | Out-Null
    Set-Content -Path (Join-Path $cfg 'pending_connect') -Value '' -NoNewline
    Start-ScheduledTask -TaskName $taskName
    Write-Host 'Запущено, жду подключения (до 2 минут)…'
    $deadline = (Get-Date).AddMinutes(2)
    $ok = $false
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        & $cliExe status *> $null
        if ($LASTEXITCODE -eq 0) { $ok = $true; break }
    }
    & $cliExe status
    if (-not $ok) {
        Write-Host ''
        Write-Host 'Не подключилось. Последние строки лога:'
        & $cliExe logs 30
        Stop-Transcript | Out-Null
        exit 1
    }
}

if ($Launch -and -not $Switch) {
    Start-ScheduledTask -TaskName $taskName
    Write-Host 'Приложение запущено'
}

Write-Host ''
Write-Host 'Готово. Запуск — ярлык WDTT (без запроса UAC). В консоли: wdtt help'
Stop-Transcript | Out-Null
exit 0
