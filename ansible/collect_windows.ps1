$ErrorActionPreference = 'Stop'
$os = Get-CimInstance Win32_OperatingSystem
$bios = Get-CimInstance Win32_BIOS
$system = Get-CimInstance Win32_ComputerSystem
@{
  'os.id' = 'windows'; 'os.family' = 'Windows'; 'os.name' = $os.Caption
  'os.version' = $os.Version; 'kernel.release' = $os.BuildNumber
  'hardware.manufacturer' = $system.Manufacturer; 'hardware.model' = $system.Model
  'hardware.serial' = $bios.SerialNumber; 'bios.version' = $bios.SMBIOSBIOSVersion
} | ConvertTo-Json -Compress
