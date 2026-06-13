# 🧾 Evidencia de validación del laboratorio — `corp.local`

> Salidas reales capturadas el **2026-06-13** durante el montaje (vía PowerShell Direct host→VM).

## DC01 — Dominio y bosque

```text
Get-ADDomain
  DNSRoot     : corp.local
  NetBIOSName : CORP
  DomainMode  : Windows2025Domain
  PDCEmulator : DC01.corp.local

Get-ADForest
  Name        : corp.local
  ForestMode  : Windows2025Forest

Servicios:  NTDS=Running  DNS=Running  kdc=Running  Netlogon=Running
Resolve-DnsName dc01.corp.local  ->  10.10.10.10
```

## DC01 — Estructura AD (FASE 2)

```text
OUs:      Employees, Servers, Workstations, ServiceAccounts, Groups, AdminAccounts (+ Domain Controllers)
Usuarios: j.perez, m.lopez, a.garcia, helpdesk, svc_sql
Grupos:   IT-Admins (j.perez) · Finance (m.lopez, a.garcia)
```

## DC01 — Señuelos de ataque de identidad

```text
Kerberoasting -> svc_sql
  SPN      : MSSQLSvc/sql01.corp.local:1433
  EncTypes : 23   (0x17 = RC4 habilitado SOLO en el señuelo, para el patrón clásico)

AS-REP Roasting -> a.garcia
  DoesNotRequirePreAuth : True
```

## WIN11 — Endpoint unido al dominio

```text
Edición       : Microsoft Windows 11 Pro   (instalación DESATENDIDA, autounattend.xml)
Hostname      : WIN11
IP            : 10.10.10.21/24   (DNS -> 10.10.10.10)
PartOfDomain  : True
Domain        : corp.local
SecureChannel : True   (relación de confianza con el DC sana)
```

## FASE 4 — GPO de auditoría (`Audit-Baseline`, enlazada al dominio)

`auditpol` en WIN11 tras `gpupdate /force` (verificado por GUID de subcategoría):

```text
Process Creation                     : Success              (4688)
Logon                                : Success and Failure  (4624/4625)
Kerberos Service Ticket Operations   : Success              (4769  -> Kerberoasting)
Kerberos Authentication Service      : Success              (4768/4771 -> AS-REP)
User Account Management              : Success              (4720/4724/4738)
ProcessCreationIncludeCmdLine_Enabled: 1                    (línea de comandos en 4688)
EnableScriptBlockLogging             : 1                    (4104)
```

Prueba **end-to-end** (genero evento → aparece en el log):

```text
Evento 4688 (Security) capturado:
  New Process Name     : C:\Windows\System32\cmd.exe
  Creator Process Name : ...\powershell.exe          <- cadena padre-hijo
  Process Command Line : cmd.exe /c "echo SOC-LAB-MARKER-4688 & ver"

Evento 4104 (Microsoft-Windows-PowerShell/Operational): scriptblock con el marcador registrado.
```

> Montado de forma scriptada: `lab-tools/Configure-AuditGPO.ps1` (políticas de registro + `audit.csv` en SYSVOL + registro del CSE de auditoría en `gPCMachineExtensionNames`).

## Telemetría — Sysmon en WIN11

Instalado con `lab-tools/Deploy-Sysmon.ps1` (config de alta señal). Servicio `Sysmon64` + driver `SysmonDrv` Running. Prueba end-to-end (Event ID 1, Process Create):

```text
Image             : ...\powershell.exe
CommandLine       : ...'SOC-LAB-SYSMON-MARKER Invoke-Expression Net.WebClient DownloadString'
User              : WIN11\labadmin
Hashes            : SHA256=0FF6F2C9...317E8C46     <- enriquecimiento de hash
ParentImage       : ...\powershell.exe             <- linaje de proceso
```

> La regla *include* de la config cazó la command line tipo loader (Invoke-Expression / Net.WebClient / DownloadString) — el mismo TTP del incidente real de origen (caso `Threat Hunting on my own PC`).

## Qué demuestra esta evidencia

- Un **dominio Active Directory funcional y aislado** (AD DS + DNS) montado de forma **reproducible y scriptada**.
- Un **endpoint Windows 11 Pro unido al dominio** instalado sin intervención (answer file).
- **Objetivos deliberados** (Kerberoasting / AS-REP Roasting) listos para la fase de Detection Engineering y Purple Team.
