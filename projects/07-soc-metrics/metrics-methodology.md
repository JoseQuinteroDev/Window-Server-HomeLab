# 📐 Metodología de métricas — cómo se computa cada número del dashboard

> El [dashboard](dashboard.html) no inventa cifras: cada KPI sale de un **artefacto real** del portfolio
> (el ruleset, los logs de alertas, las matrices de P5/P6) y es **reproducible** contra el SIEM real.
> Aquí va la **definición** de cada métrica y la **query Wazuh** para calcularla.

> **Honestidad metodológica.** Las latencias (MTTD/MTTR) provienen de **ejercicios controlados** en el lab
> aislado con ataques benignos simulados — son representativas del *pipeline de detección*, **no** SLAs de
> producción. Las cifras de inventario/cobertura son exactas (se cuentan del ruleset y las matrices).

Fuentes de datos del SIEM:
- **Ruleset:** `/var/ossec/etc/rules/local_rules.xml` (= `wazuh/rules/local_rules.xml` del repo).
- **Alertas:** `/var/ossec/logs/alerts/alerts.json` (una alerta JSON por línea).
- **Casos SOC:** `/var/ossec/logs/soc-cases.log` (Active Response `open-soc-case`, del [Proyecto 1](../01-soc-automation-playbook/automation/wazuh-active-response.md)).
- **Índice OpenSearch:** `wazuh-alerts-*` (para los mismos agregados como visualizaciones del dashboard de Wazuh).

---

## 1. Inventario de detecciones — **19 reglas**

**Definición:** número de reglas custom activas en el ruleset del lab.

```bash
grep -c '<rule id=' /var/ossec/etc/rules/local_rules.xml      # -> 19
grep -oE '<rule id="[0-9]+"' /var/ossec/etc/rules/local_rules.xml | grep -oE '[0-9]+'   # listado de IDs
```

Reglas Sigma portables (repo): 5 (P3) + 6 (P6) = **11** (`projects/0{3,6}*/detections/sigma/*.yml`, `projects/03*/sigma/*.yml`).

## 2. Cobertura ATT&CK — **14 técnicas / 8 tácticas**

**Definición:** técnicas ATT&CK únicas mapeadas por las reglas (`<mitre><id>`); tácticas = a las que pertenecen.

```bash
# Técnicas únicas declaradas en el ruleset
grep -oE '<id>T[0-9.]+</id>' /var/ossec/etc/rules/local_rules.xml | sort -u
# -> T1003.001 T1018 T1021.001 T1027 T1059.001 T1105 T1136.001 T1482 T1558.003 T1558.004 T1562.001 T1562.004 T1087.002 T1490  = 14
```
Las **8 tácticas** (Credential Access, Discovery, Defense Evasion, Execution, Persistence, Lateral Movement, Command & Control, Impact) sobre las 14 de ATT&CK Enterprise se derivan del mapeo técnica→táctica (ver [matriz P6](../06-threat-intel/attack-coverage-matrix.md)).

## 3. Alertas por severidad

**Definición:** distribución de reglas/alertas por `rule.level` (en Wazuh, nivel ≥10 = alerta).

```bash
# Por nivel, sobre las alertas reales:
jq -r '.rule.level' /var/ossec/logs/alerts/alerts.json | sort -n | uniq -c
# Inventario estático por nivel (sobre el ruleset):
grep -oE 'level="[0-9]+"' /var/ossec/etc/rules/local_rules.xml | sort | uniq -c
# -> 8x level10, 7x level12, 4x level13
```

## 4. Alertas por fuente de datos

**Definición:** qué telemetría dispara cada detección (canal / EventID).

```bash
jq -r '.data.win.system.channel // .decoder.name' /var/ossec/logs/alerts/alerts.json | sort | uniq -c
jq -r '.data.win.system.eventID' /var/ossec/logs/alerts/alerts.json | sort | uniq -c
```
> Diseño del lab: la mayoría casa `win.eventdata.commandLine`, campo **común a Security 4688 y Sysmon EID 1** → cobertura agnóstica del sensor (lección del ciclo Purple #1).

## 5. MTTD — Mean Time To Detect *(≈ segundos, lab)*

**Definición:** tiempo entre la **ocurrencia del evento** en el endpoint y la **generación de la alerta** en el manager.
`MTTD = alert.timestamp − evento.systemTime`.

```bash
# Delta por alerta (segundos) entre la hora del evento Windows y la del alertado en el SIEM:
jq -r '[( .timestamp ), ( .data.win.system.systemTime // .data.win.system.utcTime )] | @tsv' \
   /var/ossec/logs/alerts/alerts.json
# (restar ambas marcas; promediar). En el lab el delta es de segundos y lo domina el
#  intervalo de envío del agente, no la lógica de regla.
```
> **Limitación honesta:** en un lab el reloj y la carga no son los de producción; el valor demuestra que el
> *pipeline* (agente→manager→regla→alerta) opera en **tiempo casi real**, no un SLA medido sobre incidentes reales.

## 6. MTTR — apertura de caso *(≈ segundos, lab)*

**Definición:** tiempo entre la **alerta** y la **apertura automática del caso** por Active Response.
`MTTR(apertura) = caso.timestamp − alert.timestamp`.

```bash
# Casos abiertos por el AR (uno por deteccion nivel >=10):
tail -n 50 /var/ossec/logs/soc-cases.log
grep -c 'CASE-' /var/ossec/logs/soc-cases.log
```
> El AR `open-soc-case` abre el caso **sin intervención humana**, por eso el MTTR de *apertura* es de segundos.
> El MTTR de *contención/erradicación* es manual y se rige por los [runbooks del P1](../01-soc-automation-playbook/runbooks/) (no automatizado a propósito: contener requiere criterio humano).

## 7. Cobertura del bucle Purple — **85.7%**

**Definición:** técnicas emuladas en vivo que generaron ≥1 detección ÷ técnicas emuladas. Del [P5](../05-purple-team/attack-detection-matrix.md): **6/7 = 85.7%**. Con el CTI de Akira (P6), la cobertura de la cadena intra-dominio **observable** del grupo pasó de ~33% a ~100%.

## 8. Casos SOC automáticos — **7**

**Definición:** casos abiertos por el Active Response en el último ejercicio (P4/P5).

```bash
grep -c 'CASE-' /var/ossec/logs/soc-cases.log
```

## 9. Tasa de falsos positivos *(cualitativa en el lab)*

**Definición:** `FP = alertas marcadas como falso positivo en triage ÷ alertas totales`, sobre una ventana.

En el lab es **~0 por diseño**, y se explica (no se finge un número):
- **Honeypot** (100110): `svc_sql` no presta servicio real → *cualquier* 4769 hacia él es malicioso (0 FP estructural).
- **Reglas de dos condiciones** (AND sobre `commandLine`, p.ej. 100150/100190/100220) reducen el ruido frente a una sola palabra clave.
- Cada Sigma documenta sus `falsepositives` esperados (auditorías internas, herramientas de IT) → triage informado.

```bash
# En produccion se mediria etiquetando alertas (ej. con un campo de feedback) y agregando:
#   FP_rate = (alertas con veredicto=false_positive) / (alertas totales)
```

---

## Reproducir el dashboard en el SIEM de Wazuh (OpenSearch)

Los mismos agregados se construyen como **visualizaciones** sobre el índice `wazuh-alerts-*`:
- **Por severidad:** *terms aggregation* sobre `rule.level`.
- **Por táctica/técnica:** *terms* sobre `rule.mitre.tactic` / `rule.mitre.id`.
- **Por fuente:** *terms* sobre `data.win.system.channel`.
- **Tendencia / MTTD:** *date_histogram* sobre `timestamp`; *scripted field* `timestamp − data.win.system.systemTime`.
- **Cobertura ATT&CK:** el dashboard de Wazuh trae el módulo **MITRE ATT&CK** nativo (Modules → MITRE ATT&CK), alimentado por el `<mitre>` de cada regla.

> El `dashboard.html` de este proyecto es la versión **portable y demoable** (se abre sin el SIEM encendido);
> estas queries son el puente a la versión **viva** en Wazuh cuando el lab está arriba.
