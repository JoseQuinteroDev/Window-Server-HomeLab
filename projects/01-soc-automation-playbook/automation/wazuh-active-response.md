# ⚙️ Automatización — Wazuh Active Response: apertura automática de casos

> La capa de **automatización** del playbook. En un SOC cloud esto sería un Logic App / Sentinel Playbook;
> como el lab corre **Wazuh**, la automatización nativa es **Active Response (AR)**. Aquí se diseña una AR
> **lado-manager** que **abre un "caso" automáticamente** cuando dispara cualquier detección del lab
> (grupo `soc_lab`, reglas `100110`–`100161`), materializando el primer paso del ciclo *Alert → Triage*.

## Qué automatiza y por qué es segura

- **Acción:** ante una alerta del grupo `soc_lab`, anexa un **caso estructurado (JSON)** a un *casebook*
  (`/var/ossec/logs/soc-cases.log`) con regla, nivel, agente, técnica MITRE, descripción y timestamp.
- **Por qué de solo-escritura/segura:** **no** toca el endpoint, **no** mata procesos, **no** bloquea red ni
  cuentas. Solo registra un caso en el manager → cero riesgo de auto-contención errónea (un AR destructivo
  sobre un falso positivo causaría más daño que el ataque). Es el patrón correcto para empezar: **automatizar el
  triage/*ticketing*, no la respuesta destructiva**. La contención sigue siendo una decisión humana (ver
  [`../playbook/response-decision-tree.md`](../playbook/response-decision-tree.md)).
- **Valor SOC:** elimina el paso manual de "abrir ticket", normaliza los casos y deja un *audit trail* —
  insumo directo del Proyecto 7 (métricas: MTTD/MTTR, casos por severidad).

## Arquitectura

```
Detección (regla grupo soc_lab) ──► wazuh-analysisd ──► wazuh-execd (manager, root)
                                                              │
                                                              ▼
                                        active-response/bin/open-soc-case.sh
                                                              │  (alert JSON por stdin)
                                                              ▼
                                          /var/ossec/logs/soc-cases.log  (casebook)
```

## 1. Script de Active Response

`/var/ossec/active-response/bin/open-soc-case.sh` (propietario `root:wazuh`, permisos `750`):

```bash
#!/bin/bash
# Wazuh Active Response (lado-manager): abre un "caso SOC" ante una deteccion del lab.
# Lo ejecuta wazuh-execd (como root) cuando dispara una regla del grupo soc_lab.
# Recibe el alert por stdin (protocolo AR JSON) y anexa un caso estructurado al casebook.
LOG=/var/ossec/logs/soc-cases.log
J=/usr/bin/jq
read -r INPUT
CMD=$(printf '%s' "$INPUT" | $J -r '.command // "add"' 2>/dev/null)
[ "$CMD" = "delete" ] && exit 0
RID=$(printf '%s'   "$INPUT" | $J -r '.parameters.alert.rule.id // "?"' 2>/dev/null)
LVL=$(printf '%s'   "$INPUT" | $J -r '.parameters.alert.rule.level // 0' 2>/dev/null)
DESC=$(printf '%s'  "$INPUT" | $J -r '.parameters.alert.rule.description // "?"' 2>/dev/null)
AGENT=$(printf '%s' "$INPUT" | $J -r '.parameters.alert.agent.name // "?"' 2>/dev/null)
MITRE=$(printf '%s' "$INPUT" | $J -r '(.parameters.alert.rule.mitre.id // [])|join(",")' 2>/dev/null)
ATS=$(printf '%s'   "$INPUT" | $J -r '.parameters.alert.timestamp // "?"' 2>/dev/null)
CASE="CASE-$(date -u +%Y%m%d-%H%M%S)-${RID}"
printf '{"case":"%s","opened":"%s","rule":"%s","level":%s,"agent":"%s","mitre":"%s","status":"NEW","description":"%s","alert_ts":"%s"}\n' \
  "$CASE" "$(date -u +%FT%TZ)" "$RID" "$LVL" "$AGENT" "$MITRE" "$DESC" "$ATS" >> "$LOG"
exit 0
```

## 2. Configuración en el manager (`/var/ossec/etc/ossec.conf`)

```xml
<command>
  <name>open-soc-case</name>
  <executable>open-soc-case.sh</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <command>open-soc-case</command>
  <location>server</location>        <!-- se ejecuta en el manager, no en el endpoint -->
  <rules_group>soc_lab</rules_group> <!-- dispara con cualquiera de nuestras detecciones 100110-100161 -->
</active-response>
```

> `location=server` ejecuta el script en el manager (no en el agente). `rules_group=soc_lab` lo acota a las
> detecciones propias del lab (no a las miles de reglas base de Wazuh), evitando ruido. Alternativa más estricta:
> `<rules_id>100110,100120,100130,100140,100150,100151,100152,100160,100161</rules_id>`.

## 3. Despliegue

```bash
# Script al manager (vía SSH con la clave del lab)
scp -i C:\Lab\wazuh_key open-soc-case.sh socadmin@10.10.10.20:/tmp/
ssh -i C:\Lab\wazuh_key socadmin@10.10.10.20
  sudo sed -i 's/\r$//' /tmp/open-soc-case.sh                 # normaliza a LF
  sudo install -o root -g wazuh -m 750 /tmp/open-soc-case.sh \
       /var/ossec/active-response/bin/open-soc-case.sh
  # añadir los bloques <command>/<active-response> a /var/ossec/etc/ossec.conf (sección 2)
  sudo systemctl restart wazuh-manager
```

## 4. Validación

```bash
# Disparar una detección del grupo soc_lab — p.ej. Kerberoasting (100110, nivel 12) desde el DC:
#   (en DC01, PowerShell Direct)  New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken \
#                                   -ArgumentList "MSSQLSvc/sql01.corp.local:1433"
# Comprobar que el AR se ejecutó y que se abrió el caso:
sudo tail -n 5 /var/ossec/logs/active-responses.log     # registro de ejecución del AR
sudo tail -n 5 /var/ossec/logs/soc-cases.log            # el caso abierto (JSON)
```

Salida esperada en `soc-cases.log` (ejemplo):
```json
{"case":"CASE-20260615-xxxxxx-100110","opened":"...","rule":"100110","level":12,"agent":"DC01","mitre":"T1558.003","status":"NEW","description":"Kerberoasting (honeypot): TGS solicitado para la cuenta senuelo svc_sql","alert_ts":"..."}
```

## Estado — ✅ DESPLEGADA Y VALIDADA (2026-06-15)

Desplegada en el manager (`location=server`, `rules_group=soc_lab`) y **validada end-to-end**: se disparó
Kerberoasting (`100110`, nivel 12) en DC01 y el Active Response **abrió el caso automáticamente**. Entrada real
del casebook (`/var/ossec/logs/soc-cases.log`):

```json
{"case":"CASE-20260615-192139-100110","opened":"2026-06-15T19:21:39Z","rule":"100110","level":12,"agent":"DC01","mitre":"T1558.003","status":"NEW","description":"Kerberoasting (honeypot): TGS solicitado para la cuenta senuelo svc_sql","alert_ts":"2026-06-15T19:21:39.790+0000"}
```

La alerta `4769 → 100110` y la apertura del caso comparten timestamp (**19:21:39**) → automatización inmediata,
**sin intervención del analista**. El caso nace en estado `NEW`, con regla, nivel, agente y técnica MITRE ya
poblados, listo para el triage del runbook [`RB-100110`](../runbooks/RB-100110-kerberoasting.md). El casebook es
el artefacto de evidencia (un AR de `location=server` puede no escribir en `active-responses.log`; el caso en
`soc-cases.log` es la prueba definitiva de ejecución).

## Evolución (siguiente nivel de automatización)

1. **AR de enriquecimiento** (lado-agente): al disparar, recolectar automáticamente linaje del proceso (Sysmon
   EID 1) y `Get-MpThreatDetection`, y adjuntarlo al caso.
2. **AR de contención** (con guardarraíles): `firewall-drop` sobre IP de origen, o deshabilitar la cuenta AD
   implicada — **solo** para reglas de muy alta confianza (p. ej. honeypot `100110`) y con `timeout` para revertir.
3. **Integración con ticketing**: en vez del casebook local, `POST` a TheHive/Jira/Slack (en un SOC con red).
