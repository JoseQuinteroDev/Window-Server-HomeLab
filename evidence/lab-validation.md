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

## Qué demuestra esta evidencia

- Un **dominio Active Directory funcional y aislado** (AD DS + DNS) montado de forma **reproducible y scriptada**.
- Un **endpoint Windows 11 Pro unido al dominio** instalado sin intervención (answer file).
- **Objetivos deliberados** (Kerberoasting / AS-REP Roasting) listos para la fase de Detection Engineering y Purple Team.
