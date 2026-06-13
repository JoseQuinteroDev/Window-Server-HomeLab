# 🧾 Evidencia de validación — Detection Engineering

> Ataques simulados de forma controlada el **2026-06-14** contra el lab `corp.local`.
> Cada detección: técnica ATT&CK → trigger → evento capturado.

## [Det 1] Kerberoasting (T1558.003) — `4769`

Trigger: solicitud del TGS del SPN señuelo `svc_sql` (desde WIN11, 10.10.10.21).

```text
[OK] 4769 en DC01
    Account Name          : Administrator@CORP.LOCAL
    Service Name          : svc_sql
    Client Address        : ::ffff:10.10.10.21
    Ticket Encryption Type: 0x12        <-- AES, NO 0x17 (RC4)
```

> ⚠️ **Hallazgo:** Windows Server 2025 emite **AES (0x12)** aunque la cuenta soporte RC4, así que
> detectar solo por `0x17` ya no basta. Por eso `svc_sql` se trata como **honeypot/canary**:
> no presta servicio real, luego **cualquier** 4769 hacia él es sospechoso (detección enc-agnóstica).

## [Det 2] PowerShell ofuscado (T1059.001 / T1027) — `4104` + `4688`

Trigger: `powershell -EncodedCommand <b64>` cuyo scriptblock es `IEX "Write-Output 'SOC-DE-PS-MARKER'"`.

```text
[OK] 4104 (Script Block Logging) — scriptblock con IEX/marcador registrado
[OK] 4688 — proceso powershell.exe con "-EncodedCommand" en la línea de comandos
```

## [Det 3] Manipulación de Defender (T1562.001) — Sysmon `EID 1`

Trigger: `Add-MpPreference -ExclusionPath ...` por línea de comandos (se revierte al instante).

```text
[OK] Sysmon Event ID 1
    CommandLine : powershell.exe -NoProfile -Command "Add-MpPreference -ExclusionPath 'C:\soc-de-test-REMOVEME' ...; Remove-MpPreference ..."
    User        : WIN11\labadmin
    ParentImage : ...\powershell.exe
```

> Es el mismo TTP del incidente real de origen (el atacante se auto-excluyó en Defender).

## [Det 5] LOLBin de descarga (T1105) — `4688`

Trigger: `certutil -urlcache -f http://127.0.0.1/soc-de-test ...` (URL local, no descarga nada real).

```text
[OK] 4688 (Security)
    New Process Name     : C:\Windows\System32\certutil.exe
    Creator Process Name : ...\powershell.exe
    Process Command Line : certutil.exe -urlcache -f http://127.0.0.1/soc-de-test ...
```

> 🔎 **Lección de fuentes de datos:** la config de Sysmon es de **alta señal** y NO incluye `certutil`,
> así que esta técnica **no** generó Sysmon EID 1 — la cazó el **Security 4688**. Conclusión:
> Sysmon y la auditoría de Windows son **complementarios**, no redundantes.

## [Det 4] AS-REP Roasting (T1558.004) — pendiente de disparo

```text
SamAccountName        : a.garcia
DoesNotRequirePreAuth : True      <-- señuelo presente y roasteable
```

> La lógica (Sigma/KQL sobre `4768` con `PreAuthType=0`) está lista. El disparo real de un AS-REQ sin
> preautenticación requiere una herramienta ofensiva (Rubeus / impacket `GetNPUsers`) → se valida
> cuando se incorpore **KALI** al lab (diferido por disco).

---

## Resumen

| # | Detección | ATT&CK | Fuente | Disparado | Capturado |
|---|---|---|---|---|---|
| 1 | Kerberoasting (honeypot svc_sql) | T1558.003 | Security 4769 | ✅ | ✅ |
| 2 | PowerShell ofuscado | T1059.001 | 4104 + 4688 | ✅ | ✅ |
| 3 | Tamper Defender (Add-MpPreference) | T1562.001 | Sysmon EID 1 | ✅ | ✅ |
| 5 | LOLBin descarga (certutil) | T1105 | Security 4688 | ✅ | ✅ |
| 4 | AS-REP Roasting | T1558.004 | Security 4768 | ⏳ (KALI) | lógica lista |
