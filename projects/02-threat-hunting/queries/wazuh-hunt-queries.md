# 🧰 Queries de caza — Wazuh (`jq` sobre `alerts.json`) + origen (`Get-WinEvent`)

> Todas ejecutadas en vivo (2026-06-15). En el manager (`ssh -i C:\Lab\wazuh_key socadmin@10.10.10.20`) el fichero es
> `/var/ossec/logs/alerts/alerts.json` (una alerta JSON por línea). Campos del decoder: `win.system.eventID`,
> `win.system.channel`, `win.eventdata.*` (1ª letra minúscula). En origen se caza con `Get-WinEvent` por PowerShell Direct.

## 0 · Inventario de telemetría (¿qué tengo para cazar?)
```bash
F=/var/ossec/logs/alerts/alerts.json
sudo tail -n 20000 $F | jq -r '.data.win.system.eventID // empty' | sort | uniq -c | sort -rn   # por evento
sudo tail -n 20000 $F | jq -r '.data.win.system.channel // empty' | sort | uniq -c | sort -rn   # por canal
sudo tail -n 20000 $F | jq -r '.agent.name // empty'              | sort | uniq -c | sort -rn   # por agente
```

## H1 · PowerShell ofuscado (4104)
```bash
# scriptblocks que casan indicadores de cradle/ofuscación
sudo tail -n 20000 $F | jq -r 'select(.data.win.system.eventID=="4104")
  | (.data.win.eventdata.scriptBlockText // "-")' \
  | grep -iE 'FromBase64String|Invoke-Expression|\bIEX\b|DownloadString|Net\.WebClient|-EncodedCommand'
```
```powershell
# Origen (WIN11): 4104 recientes
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 50 |
  Where-Object Message -match 'IEX|EncodedCommand|DownloadString'
```

## H2 · LOLBins de descarga (4688 / Sysmon, `commandLine`)
```bash
# ranking de binarios en líneas de comando + foco en LOLBins de descarga
sudo tail -n 20000 $F | jq -r '(.data.win.eventdata.commandLine // empty)' \
  | grep -ioE '[a-z0-9_]+\.exe' | grep -iE 'certutil|bitsadmin|mshta|rundll32|regsvr32|wmic' \
  | sort | uniq -c | sort -rn
# detalle de certutil con flags de descarga
sudo tail -n 20000 $F | jq -r 'select((.data.win.eventdata.commandLine//"")|test("certutil";"i"))
  | [.timestamp[11:19], .rule.id, .data.win.eventdata.commandLine] | @tsv'
```

## H3 · Evasión de Defender + el EDR como pista
```bash
# tamper por línea de comandos
sudo tail -n 20000 $F | jq -r 'select((.data.win.eventdata.commandLine//"")
  | test("Add-MpPreference|-ExclusionPath|DisableRealtimeMonitoring";"i"))
  | [.timestamp[11:19], .rule.id, .data.win.eventdata.commandLine] | @tsv'
# detecciones del propio Defender (1116 detección / 1117 acción)
sudo tail -n 20000 $F | jq -r 'select(.data.win.system.eventID=="1116" or .data.win.system.eventID=="1117")
  | [.timestamp[11:19], .data.win.system.eventID, (.data.win.eventdata."threat Name"//"-")] | @tsv'
```

## H4 · Persistencia — servicios nuevos (7045)
```bash
sudo tail -n 20000 $F | jq -r 'select(.data.win.system.eventID=="7045")
  | [.timestamp[11:19], (.data.win.eventdata.serviceName//"-"), (.data.win.eventdata.imagePath//"-")] | @tsv'
```

## H5 · Kerberoasting — config + 4769
```powershell
# Config hunt en el DC (PowerShell Direct, CORP\Administrator): cuentas de usuario con SPN
Get-ADUser -Filter "ServicePrincipalName -like '*'" -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes
# TGS crudos hacia el señuelo svc_sql con su tipo de cifrado
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 40 |
  Where-Object Message -match 'svc_sql'   # -> ServiceName=svc_sql, TicketEncryptionType=0x12 (AES)
```
```bash
# En el SIEM: honeypot (cualquier TGS a svc_sql) y clásico (RC4 0x17)
sudo tail -n 20000 $F | jq -r 'select(.data.win.system.eventID=="4769")
  | [.timestamp[11:19], (.data.win.eventdata.serviceName//"-"), (.data.win.eventdata.ticketEncryptionType//"-")] | @tsv'
```

## H6 · AS-REP roastable — config hunt
```powershell
# Cuentas con preautenticación desactivada (en el DC)
Get-ADUser -Filter "DoesNotRequirePreAuth -eq 'True'" -Properties DoesNotRequirePreAuth   # -> a.garcia
```
```bash
# 4768 sin preautenticación (cuando se dispare con Rubeus/impacket)
sudo tail -n 20000 $F | jq -r 'select(.data.win.system.eventID=="4768" and .data.win.eventdata.preAuthType=="0")
  | [.timestamp[11:19], (.data.win.eventdata.targetUserName//"-")] | @tsv'
```
