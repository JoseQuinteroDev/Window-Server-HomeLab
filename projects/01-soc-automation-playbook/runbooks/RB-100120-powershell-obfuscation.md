# 🛠️ Runbook 100120 — PowerShell ofuscado / cradles

> **Regla(s) Wazuh:** 100120 · **ATT&CK:** T1059.001 Command and Scripting Interpreter: PowerShell + T1027 Obfuscated Files or Information (Execution / Defense Evasion) · **Severidad:** Alta (nivel 12)

## 1. Disparo

La regla 100120 dispara con eventos **4104 (Script Block Logging, canal `Microsoft-Windows-PowerShell/Operational`)** cuyo `scriptBlockText` casa el regex de ofuscacion:

```
FromBase64String | Invoke-Expression | IEX | DownloadString | Net.WebClient | -EncodedCommand
```

Origen del evento: **WIN11 (10.10.10.21)**, con Script Block Logging activo. La condicion es de **contenido** (no determinista como el honeypot 100110): cualquier bloque de script que contenga uno de esos tokens eleva a nivel 12. Esto incluye cradles de descarga reales **y** funciones internas legitimas de PowerShell, por lo que el triage manda.

## 2. Triage inicial (objetivo: TP/FP en < 5 min)

Checklist, en orden:

1. **Leer el `scriptBlockText` completo.** Es el dato decisivo.
2. **Contrastar con el BASELINE de known-good del lab (Proyecto 2).** Marcar como **probable FP** si el texto es actividad ADMIN legitima:
   - Funciones internas de `Copy-Item -ToSession`: `PSCopyFileToRemoteSession`, `CheckPSDriveSize`, `PSCopyToSessionHelper`. Estas contienen `FromBase64String` por diseño (serializan el fichero) y son la causa #1 de ruido.
   - Scripts de inventario `.inf` y reinstalacion de Sysmon ejecutados por el admin.
3. **Criterio de TP real:** un **cradle** explicito — `IEX (New-Object Net.WebClient).DownloadString('http://...')` o el bloque resultante de decodificar un `-EncodedCommand`. Señales fuertes: descarga remota (`DownloadString`/`Net.WebClient` con URL), `IEX` sobre cadena dinamica, o Base64 que decodifica a mas codigo.
4. **¿Quien lo ejecuto?** Si es `CORP\Administrator` en ventana de mantenimiento conocida → peso hacia FP. Si es `j.perez`/`m.lopez`/`helpdesk` lanzando descargas remotas → peso fuerte hacia TP.
5. **¿Hubo deteccion de Defender correlacionada (100160/100161) en el mismo host/ventana?** Si Defender detecto+bloqueo algo → TP, escalar.

Si tras el checklist es claramente una funcion interna de `-ToSession` ejecutada por admin conocido → **FP**, ir a §6 y añadir al baseline. En cualquier otro caso → continuar §3.

## 3. Enriquecimiento

Recolectar (enriquecimiento **LOCAL**, que es el disponible en el lab aislado):

**a) El bloque 4104 completo y su contexto, sobre `alerts.json`:**

```bash
jq -r 'select(.rule.id=="100120")
  | {ts:.timestamp, agent:.agent.name, user:.data.win.eventdata.targetUserName,
     channel:.data.win.system.channel, script:.data.win.eventdata.scriptBlockText}' \
  /var/ossec/logs/alerts/alerts.json
```

**b) El `commandLine` real con el `-EncodedCommand`** — vive en el **4688** (proceso creado), NO en el 4104. La regla base 67027 alerta en cada 4688, asi que pivotar por la ventana temporal sobre esos eventos:

```bash
jq -r 'select(.data.win.system.eventID=="4688"
        and (.data.win.eventdata.newProcessName|test("powershell|pwsh";"i")))
  | {ts:.timestamp, user:.data.win.eventdata.targetUserName,
     cmd:.data.win.eventdata.commandLine}' \
  /var/ossec/logs/alerts/alerts.json
```

> Nota: el **proceso padre** (linaje) NO esta de forma fiable en el 4688; se obtiene del Sysmon EID 1 (`parentImage`), §3.c.

**c) Linaje del proceso (Sysmon EID 1: que lanzo el powershell + hash SHA256)** — por PowerShell Direct desde el host (red aislada):

```powershell
Invoke-Command -VMName WIN11 -Credential $cred -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 50 |
    Where-Object { $_.Message -match 'powershell|pwsh' } |
    Select-Object TimeCreated,
      @{n='Image';e={($_.Message -split "`n" | Select-String 'Image:').Line}},
      @{n='ParentImage';e={($_.Message -split "`n" | Select-String 'ParentImage:').Line}},
      @{n='Hashes';e={($_.Message -split "`n" | Select-String 'Hashes:').Line}}
}
```

**d) Decodificar el `-EncodedCommand`** (Base64 UTF-16LE) para ver el cradle real, en el host:

```powershell
$b64 = '<cadena Base64 capturada del commandLine>'
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
```

**e) Usuario en AD (contexto + privilegios), por PS Direct contra DC01:**

```powershell
Invoke-Command -VMName DC01 -Credential $cred -ScriptBlock {
  Get-ADUser -Identity 'j.perez' -Properties MemberOf, LastLogonDate |
    Select-Object SamAccountName, Enabled, LastLogonDate, MemberOf
}
```

**f) Estado del endpoint (¿Defender ya vio algo?):**

```powershell
Invoke-Command -VMName WIN11 -Credential $cred -ScriptBlock { Get-MpThreat; Get-MpComputerStatus }
```

**Enriquecimiento EXTERNO (CONCEPTUAL — no disponible en el lab aislado):** en un SOC real, con la URL/dominio del cradle y el SHA256 del payload se haria lookup de reputacion en **VirusTotal / AbuseIPDB / OTX** (plantilla de IoC lookup) para confirmar si el host/hash es malicioso conocido y obtener atribucion.

## 4. Investigacion

Preguntas a responder y pivotes:

- **Linaje:** ¿que proceso padre lanzo el `powershell.exe`? (`parentImage` de Sysmon EID 1, §3.c). Un padre como `winword.exe`, `mshta.exe`, `wscript.exe` o `explorer.exe` desde un adjunto = altamente sospechoso; `wsmprovhost.exe`/`services.exe` en ventana de admin = peso hacia FP.
- **Contenido del cradle:** tras decodificar (§3.d), ¿hay una URL de descarga? ¿que descarga (`.ps1`, `.exe`, `.dll`)? ¿se ejecuta en memoria via `IEX`?
- **Usuario y privilegios:** ¿la cuenta (§3.e) tiene sentido para esa accion? ¿es cuenta privilegiada o de servicio?
- **Temporalidad:** ¿coincide con una ventana de mantenimiento de admin conocida, o es fuera de horario?
- **Alcance / correlacion:** ¿hay LOLBins relacionados en la misma ventana — certutil (100150), bitsadmin (100151), mshta (100152) — que completen una cadena de descarga? ¿Detecciones de Defender (100160/100161) en el mismo host?
- **Resultado de la descarga:** si hubo `DownloadString` con URL, ¿quedo el payload en disco? Buscarlo por el linaje y por escrituras de fichero posteriores.

## 5. Respuesta

Proporcional a la severidad (nivel 12):

**Si es TP (cradle de descarga real):**
1. **Aislar WIN11** de la red del lab (en Hyper-V: desconectar el adaptador de red de la VM; la operacion sigue por PowerShell Direct desde el host, que no depende de red).
2. **Capturar evidencia antes de tocar nada:** guardar el `scriptBlockText`, el `commandLine` decodificado, el hash SHA256 del `powershell.exe`/payload y, si quedo en disco, el fichero del payload.
3. **Buscar el payload:** seguir el linaje y las URLs del cradle; localizar lo descargado y ponerlo en cuarentena/copia para analisis.
4. **Revisar Defender** (`Get-MpThreat`): si bloqueo → defensa en profundidad confirmada (como en el certutil `Trojan:Win32/Ceprolad.A`, 1116/1117); si no → posible evasion, subir prioridad.
5. **Escalar a IR (PICERL).** Este runbook llega a la **respuesta inicial y handoff**; la contencion/erradicacion/recuperacion completas se ejecutan en el Proyecto 4.

**Si es FP (funcion interna `-ToSession` / actividad admin conocida):**
1. Cerrar el caso como FP documentado.
2. **Añadir al baseline de known-good** (firma del `scriptBlockText` + usuario admin) para reducir ruido futuro; considerar afinar la regla 100120 con exclusiones para `PSCopyFileToRemoteSession`/`CheckPSDriveSize`/`PSCopyToSessionHelper` cuando el actor sea admin.

## 6. Documentacion

Registrar en el caso:

- **Veredicto:** TP / FP y criterio que lo decidio (§2).
- **Campos clave:** `timestamp`, `agent.name` (WIN11), `targetUserName`, `scriptBlockText` (bloque 4104), `commandLine` completo (4688) y su decodificacion del `-EncodedCommand`, `parentImage` + `Hashes` SHA256 (Sysmon EID 1).
- **IoCs:** URL/dominio del cradle, SHA256 del `powershell.exe` y del payload, nombre del fichero descargado, cuenta de usuario.
- **Correlacion:** IDs de alertas relacionadas (100150/100151/100152 LOLBins; 100160/100161 Defender).
- **Enriquecimiento externo pendiente** (conceptual): resultado esperado de VT/AbuseIPDB/OTX sobre la URL y el SHA256.
- **Decision y handoff:** cierre como FP + entrada de baseline, o escalado a IR con la evidencia capturada.

## 7. Automatizacion aplicable

Con **Wazuh Active Response (lado-manager)**, la alerta de nivel ≥12 **abre un caso automaticamente** y adjunta el `scriptBlockText`, usuario y agente (apertura de ticket/enriquecimiento, solo-lectura y segura). Se puede encadenar un script de enriquecimiento que correlacione por ventana temporal el 4688 (commandLine/`-EncodedCommand`) y las alertas LOLBin/Defender del mismo host, dejando el triage de §2–§3 pre-rellenado. El aislamiento del host (§5) se mantiene **manual/aprobado** dado el riesgo de cortar operaciones legitimas de admin.