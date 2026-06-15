# 🔎 Hunt H6 — Cuentas AS-REP roastables (config hunt)

> **Credential Access** · MITRE ATT&CK **T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting**

## Hipótesis

Sospechamos que existen cuentas de usuario en `corp.local` con la preautenticación Kerberos desactivada (flag `DONT_REQ_PREAUTH`). Cualquier atacante con conectividad al KDC —sin necesidad de credenciales válidas— puede solicitar el AS-REP de esas cuentas, recibir un blob cifrado con material derivado del hash de la contraseña y crackearlo offline. Cazamos la **exposición de configuración** de forma proactiva, antes de que se materialice un AS-REQ de roasting real.

## Técnica ATT&CK

**T1558.004 — AS-REP Roasting** (táctica *Credential Access*). En Kerberos, la preautenticación obliga al cliente a probar que conoce la contraseña (cifrando un timestamp, PA-ENC-TIMESTAMP) antes de que el KDC emita el AS-REP. Cuando una cuenta tiene `DONT_REQ_PREAUTH` activo, el KDC entrega el AS-REP a quien lo pida; ese mensaje incluye una porción cifrada con la clave derivada de la contraseña del usuario, que el atacante somete a fuerza bruta/diccionario offline (hashcat modo 18200). El roasting deja un **4768 (AS-REQ) con `Pre-Authentication Type = 0`** en el KDC.

## Fuente de datos

- **Config de AD (fuente primaria de esta caza)**: estado del atributo `userAccountControl` / `DoesNotRequirePreAuth` en DC01 (10.10.10.10, KDC). Detecta la exposición sin depender de que ocurra un ataque.
- **Security 4768** (canal *Security*, ingerido por Wazuh desde DC01): AS-REQ de Kerberos. El campo `win.eventdata.preAuthType = 0` es la firma del roasting cuando se ejecute. Es la fuente de detección reactiva que complementa al config hunt.
- Razón del enfoque dual: la metodología de caza exige mirar **la telemetría/estado crudo**, no solo lo que ya disparó una regla. Aquí el "estado crudo" es la propia configuración de AD en el KDC, enumerada en origen.

## La caza

### Wazuh (alerts.json, jq en el manager)

El disparo real del 4768 con `preAuthType = 0` requiere una herramienta de roasting (Rubeus / impacket `GetNPUsers`) que **aún no se ha ejecutado** (KALI diferido). La query queda lista y validada para cuando haya tráfico de ataque:

```bash
# AS-REQ (4768) SIN preautenticacion -> firma de AS-REP Roasting
jq -c 'select(.data.win.system.eventID == "4768"
        and .data.win.eventdata.preAuthType == "0")
       | {ts: .timestamp,
          user: .data.win.eventdata.targetUserName,
          preAuth: .data.win.eventdata.preAuthType,
          enc: .data.win.eventdata.ticketEncryptionType,
          srcIP: .data.win.eventdata.ipAddress,
          rule: .rule.id}' /var/ossec/logs/alerts/alerts.json

# Confirmar que la regla dedicada 100140 ya cubre el evento cuando llegue
jq -c 'select(.rule.id == "100140")
       | {ts: .timestamp, user: .data.win.eventdata.targetUserName,
          desc: .rule.description}' /var/ossec/logs/alerts/alerts.json
```

> Estado actual: ambas queries devuelven **0 resultados** — no hay AS-REQ sin preauth en el histórico, coherente con que el roasting no se ha lanzado. La caza no se queda aquí: pivota al estado de configuración en origen.

> Nota de campo: `ipAddress` es el cliente del AS-REQ (Client Address del 4768). En entornos reales puede aparecer en formato IPv6-mapeado (`::ffff:10.10.10.x`); conviene normalizarlo al correlacionar el origen.

### Origen — config de AD (PowerShell Direct sobre DC01)

El núcleo del config hunt: enumerar directamente en el KDC qué cuentas tienen el flag puesto. No depende de ningún evento.

```powershell
# DC01 (10.10.10.10) — cuentas con preautenticacion Kerberos desactivada
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' `
           -Properties DoesNotRequirePreAuth, userAccountControl, servicePrincipalName |
    Select-Object SamAccountName, Enabled, DoesNotRequirePreAuth, userAccountControl |
    Format-Table -AutoSize

# Verificacion cruzada por el bit de userAccountControl
# (DONT_REQ_PREAUTH = 0x400000 = 4194304). El filtro del proveedor AD NO admite
# el operador -band; el bitwise se hace con la matching-rule OID LDAP_MATCHING_RULE_BIT_AND
# (1.2.840.113556.1.4.803) via -LDAPFilter.
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' `
           -Properties userAccountControl |
    Select-Object SamAccountName, Enabled, userAccountControl
```

### KQL (Sentinel / Defender XDR — equivalente)

No se ejecuta en el lab (corre Wazuh); se incluye como se vería en un SIEM cloud para la parte de detección reactiva del 4768:

```kql
// AS-REP Roasting — AS-REQ sin preautenticacion (Pre-Auth Type 0)
SecurityEvent
| where EventID == 4768
| where PreAuthType == "0"
| project TimeGenerated, TargetUserName, PreAuthType, TicketEncryptionType, IpAddress, Computer
| sort by TimeGenerated desc
```

## Hallazgos (datos REALES del lab)

| Vector de caza | Resultado | Detalle |
|---|---|---|
| Config hunt en DC01 (`Get-ADUser DoesNotRequirePreAuth -eq $true`) | **1 cuenta expuesta** | `a.garcia` — tiene `DONT_REQ_PREAUTH = True` |
| Naturaleza de la cuenta | **Señuelo (honeypot)** | `a.garcia` es el cebo de AS-REP Roasting plantado en AD a propósito |
| Wazuh 4768 `preAuthType = 0` (alerts.json) | **0 eventos** | El roasting real no se ha ejecutado (KALI diferido); no hay AS-REQ sin preauth |
| Regla de detección 100140 | **Armada, sin disparos** | Cubrirá el 4768 `preAuthType 0` en cuanto haya un roasting real |

**Conclusión del hallazgo:** existe una superficie de ataque AS-REP real y confirmada (`a.garcia`), encontrada por **caza de configuración** antes de cualquier intento de explotación. La cuenta es el señuelo previsto, lo que valida que el control de exposición funciona.

## Triage: known-good vs malicioso

- **Justificación del flag**: `DONT_REQ_PREAUTH` casi nunca es legítimo en un dominio moderno. Se ve en cuentas de compatibilidad con clientes Kerberos antiguos/no-Windows o appliances; cualquier otra cuenta con el flag es sospechosa por defecto. Validar contra un inventario de excepciones aprobadas.
- **En este lab**: `a.garcia` es un **señuelo conocido** — no es una cuenta de servicio ni de usuario real con justificación operativa. Su único propósito es detectar roasting. Cualquier AS-REQ `preAuthType 0` contra `a.garcia` debe tratarse como **malicioso por definición** (nadie debería pedir su AS-REP salvo un atacante enumerando cuentas roastables).
- **Separar ruido de amenaza en el 4768**: un 4768 normal lleva `preAuthType` no nulo (típicamente `2`, PA-ENC-TIMESTAMP). Solo `preAuthType = 0` es la firma de roasting. Correlacionar `targetUserName`, `ipAddress` de origen y `ticketEncryptionType` (un `0x17`/RC4 además refuerza la sospecha por crackeo más rápido).

## Outcome

Doble acción derivada de la caza:

1. **Hardening (reduce superficie):** quitar el flag `DONT_REQ_PREAUTH` de `a.garcia` si no responde a una necesidad operativa real —en este lab es un señuelo, por lo que el flag se mantiene de forma deliberada y documentada como trampa de detección; en producción se eliminaría—. Comando de remediación: `Set-ADAccountControl -Identity a.garcia -DoesNotRequirePreAuth $false`. Endurecer además la política de contraseñas para que un AS-REP capturado no sea crackeable offline.
2. **Detección (ya cubierta):** la **regla Wazuh 100140** (AS-REP, 4768 `preAuthType 0`) ya está desplegada y armada; disparará en cuanto se lance un roasting real (Rubeus / impacket `GetNPUsers`) contra `a.garcia` o cualquier otra cuenta del dominio. No se requiere regla nueva; la cobertura de detección está confirmada.

**Valor demostrado:** caza **proactiva basada en exposición de configuración** —la amenaza se identifica por el estado de AD antes de que exista un solo evento de ataque— complementada por una detección reactiva (100140) ya operativa para el momento de la explotación.
