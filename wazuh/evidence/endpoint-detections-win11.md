# 🛡️ Evidencia — validación de detecciones de endpoint en WIN11 (Wazuh)

> **Fecha:** 2026-06-15 · **Analista:** José Quintero · **Lab:** `corp.local` (Hyper-V, LAB-Net aislado)
> **SIEM:** Wazuh 4.13.1 (manager `10.10.10.20`) · **Endpoint:** `WIN11` (10.10.10.21, unido al dominio)
>
> Continuación de [`first-alert-kerberoasting.md`](first-alert-kerberoasting.md) (detección en el DC). Aquí se
> despliega el agente en el **endpoint** y se validan las detecciones que viven en el host: PowerShell,
> evasión de defensas y LOLBins. Todo disparado de forma controlada por PowerShell Direct desde el host.

---

## 1. Agente Wazuh en WIN11

Desplegado por PowerShell Direct (sin red) con `lab-tools/Deploy-WazuhAgent.ps1`: copia del MSI por VMBus
(`Copy-Item -ToSession`), instalación + auto-enrolamiento contra el manager y alta de los canales de eventos
(Sysmon + PowerShell/Operational además de Security/System por defecto).

```
$ /var/ossec/bin/agent_control -l
   ID: 000, Name: wazuh (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: DC01,  IP: any, Active
   ID: 002, Name: WIN11, IP: any, Active      <-- nuevo
```

> Restricción operativa del lab (host 16 GB RAM): **WAZUH + UNA Windows a la vez**. Para esta validación se
> levantaron WAZUH + WIN11 y DC01 quedó en *Saved*. Las detecciones de endpoint no necesitan el DC.

---

## 2. Detecciones validadas (end-to-end)

Simulador: `projects/03-detection-engineering/tests/Invoke-DetectionTests.ps1` (triggers 2–4, inofensivos).

| Regla | Técnica (ATT&CK) | Evento fuente | Nivel | Estado |
|-------|------------------|---------------|:----:|:------:|
| **100120** PowerShell ofuscado | T1059.001 / T1027 | PowerShell/Operational **4104** | 12 | ✅ |
| **100130** Tamper de Defender | T1562.001 | Sysmon EID 1 / Security **4688** (`commandLine`) | 12 | ✅ |
| **100150** LOLBin `certutil` | T1105 | Security **4688** (`commandLine`) | 10 | ✅ *(tras el fix de §3)* |
| **100160** Defender — malware detectado | (EDR) | Defender/Operational **1116** | 12 | ✅ *(nueva, §4)* |
| **100161** Defender — acción de protección | (EDR) | Defender/Operational **1117** | 10 | ✅ *(nueva, §4)* |

100120 mostró el `scriptBlockText` real en la alerta: `IEX "Write-Output 'SOC-DE-PS-MARKER'"`.
Junto con **100110 (Kerberoasting, T1558.003)** validada en DC01, son **6 detecciones probadas en vivo**.
**100140 (AS-REP, T1558.004)** sigue diferida: requiere disparo real con Rubeus/KALI.

---

## 3. Hallazgo de ingeniería de detección — el *true negative* de `certutil`

**Síntoma:** se lanzó `certutil.exe -urlcache -f http://127.0.0.1/... ` (T1105) y la regla 100150 **no disparó**,
aunque el evento sí se ingirió (apareció como la regla genérica `67027`, *"A process was created"*, nivel 3).

**Causa raíz (dos capas):**
1. La regla original casaba `win.eventdata.image`, un campo que **solo emite Sysmon (EID 1)**.
2. El Sysmon de alta señal del lab usa `ProcessCreate onmatch="include"` y su lista **no incluía** `certutil`
   → **no se genera EID 1** para él. El único evento disponible fue **Security 4688**, donde la imagen del
   proceso vive en `newProcessName` (no en `image`) → la condición `image` nunca casaba (`image=null`).

Evento crudo que lo demuestra (4688, no Sysmon):
```json
{ "rule.id":"67027", "groups":["windows"], "image":null, "eventID":"4688", "channel":"Security",
  "commandLine":"\"C:\\WINDOWS\\system32\\certutil.exe\" -urlcache -f http://127.0.0.1/soc-de-test ..." }
```

**Fix:** alinear 100150/100151/100152 para casar **`win.eventdata.commandLine`** — el campo **común a Sysmon
EID 1 y a Security 4688** — exactamente el patrón que ya hacía robusta a la 100130 (Defender). La regla queda
**agnóstica del sensor** y **resistente a tamper de Sysmon** (apagar Sysmon + descargar con certutil ya no nos
ciega). `wazuh-analysisd -t` OK → recarga → el ataque vuelve a dispararse y **100150 dispara** (14:15:03+).

> Lección: una regla atada a un único sensor es un punto ciego. Casar el campo común a varias fuentes
> (`commandLine`) da cobertura aunque falte o se manipule un sensor.

---

## 4. Defensa en profundidad — Defender detecta y **bloquea** el LOLBin (y cerramos el gap de telemetría)

Al repetir los disparos, `certutil` empezó a devolver **"Access is denied"**: **Microsoft Defender** reconoció
el patrón `certutil -urlcache` y lo clasificó como **`Trojan:Win32/Ceprolad.A`** (ThreatID 2147726914),
escalando de detectar a **bloquear** la ejecución (RTP activo).

```
Get-MpThreat        -> Trojan:Win32/Ceprolad.A
Defender/Operational-> EID 1116 (detección) + EID 1117 (acción tomada)
```

**Gap descubierto:** esos eventos del propio EDR **no llegaban al SIEM** (el canal
`Microsoft-Windows-Windows Defender/Operational` no se ingería). Se perdía telemetría de altísima señal:
*el antivirus confirmando un bloqueo real.*

**Cierre del gap:**
- Canal añadido al agente (`wazuh/agent/windows-eventchannel.conf` + `ossec.conf` de WIN11).
- Reglas nuevas **100160** (1116, detección, nivel 12) y **100161** (1117, acción, nivel 10).

**Validación (14:28):** sobre el *mismo* `certutil`, disparan a la vez **100150** (nuestra regla vía 4688)
**y 100160/100161** (Defender bloqueando). Tres señales independientes para una técnica (T1105) — defensa en
profundidad demostrada en el SIEM.

> Nota Sysmon: se añadieron `certutil`/`bitsadmin` al `ProcessCreate include` (higiene estándar de LOLBins,
> aporta hash SHA256 + linaje). La generación de su EID 1 **no pudo confirmarse en esta sesión** porque
> Defender pasó a **bloquear** `certutil` antes de que el proceso llegara a crearse limpiamente. No afecta a la
> cobertura: T1105 queda cubierta por 100150 (4688) y por 100160/161 (el propio Defender).

---

## 5. Cómo reproducir

```powershell
# Host (admin): WAZUH + WIN11 arriba, DC01 puede quedar Saved
.\lab-tools\Deploy-WazuhAgent.ps1 -VMName WIN11 -User 'WIN11\labadmin' -Password '<lab>'
# disparar triggers de endpoint (PowerShell 4104, tamper Defender, certutil) por PS Direct
# y revisar en el dashboard Wazuh (Threat Hunting / MITRE) o en /var/ossec/logs/alerts/alerts.json
```
```bash
# Manager: comprobar las alertas de nuestras reglas
sudo tail -n 4000 /var/ossec/logs/alerts/alerts.json \
 | jq -r 'select(.rule.id|test("^1001(20|30|50|60|61)$")) | [.timestamp[11:19],.agent.name,.rule.id,.rule.description] | @tsv'
```
