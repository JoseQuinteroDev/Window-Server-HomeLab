# 🛰️ Wazuh — SIEM self-hosted del lab (offline, dentro de LAB-Net)

> **SIEM elegido para el portfolio: Wazuh** (open source, gratis, sin nube ni tarjeta).
> Cierra la columna **Deploy & Monitor** del [Proyecto 3](../projects/03-detection-engineering/):
> nuestras detecciones se cargan como **reglas Wazuh** y disparan **alertas reales** en el dashboard.

---

## ¿Por qué Wazuh (y no Sentinel)?

| | Wazuh (elegido) | Microsoft Sentinel (variante cloud en [`../sentinel/`](../sentinel/)) |
|---|---|---|
| Coste | **100% gratis**, open source | "Gratis" con suscripción Azure + tarjeta + limpieza |
| Red | **Corre entero en `LAB-Net` aislado**, sin internet | Necesita salida a la nube |
| Host | No toca el host (que ya sufrió un incidente) | — |
| De fábrica | Alertas, decoders Windows/Sysmon, **mapeo MITRE ATT&CK** | KQL (keyword nº1 en ofertas) |

Wazuh encaja con la filosofía del lab (aislado, reproducible, sin depender de terceros). Se conserva el kit de
Sentinel por si algún día interesa el keyword **KQL** en el CV — las dos rutas comparten la misma lógica de detección.

---

## Arquitectura (todo en `LAB-Net`, 10.10.10.0/24 — aislado)

```
        ┌──────────────────────────────────────────────────────────┐
        │  vSwitch LAB-Net (Internal, SIN gateway / SIN internet)    │
        │                                                            │
        │   DC01  10.10.10.10 ──┐                                    │
        │   (agente Wazuh)      │                                    │
        │                       ├──►  WAZUH  10.10.10.20             │
        │   WIN11 10.10.10.21 ──┘     (manager all-in-one:           │
        │   (agente Wazuh)             indexer + server + dashboard) │
        └──────────────────────────────────────────────────────────┘

   Flujo:  Sysmon + Security + PowerShell/Operational  (eventchannel)
             → agente Wazuh → manager → decoders → local_rules.xml → ALERTA (dashboard)
```

- **VM `WAZUH`** — Ubuntu Server 24.04, Wazuh 4.x *all-in-one*. Gen2, 2 vCPU, 4 GB RAM, VHDX dinámico 32 GB.
- **Agentes Wazuh** en `DC01` (eventos AD/Kerberos: 4768/4769) y `WIN11` (Sysmon, 4688, PowerShell 4104).
- Internet **solo durante la instalación** (apt + instalador Wazuh) vía `Default Switch`; luego se retira y el lab vuelve a quedar aislado. Ver [`deploy-wazuh-runbook.md`](deploy-wazuh-runbook.md).

> **Dimensionado (host 16 GB RAM):** DC01 (2) + WIN11 (4) + WAZUH (4) + host (~4) ≈ **14 GB**, viable.
> Regla: **no encender KALI a la vez** que las tres. Disco: tras la limpieza hay ~51 GB libres en C:.

---

## Detecciones (portadas del Proyecto 3 → reglas Wazuh)

Fichero: [`rules/local_rules.xml`](rules/local_rules.xml) · Ingesta: [`agent/windows-eventchannel.conf`](agent/windows-eventchannel.conf)

| Rule ID | Detección | MITRE | Fuente / Evento |
|---|---|---|---|
| 100110 | Kerberoasting — honeypot `svc_sql` (enc-agnóstico) | T1558.003 | Security **4769** |
| 100111 | Kerberoasting — TGS con RC4 (`0x17`) | T1558.003 | Security **4769** |
| 100120 | PowerShell ofuscado (Base64/IEX/DownloadString…) | T1059.001 / T1027 | PowerShell/Operational **4104** |
| 100130 | Manipulación de Defender (exclusiones, RTP off) | T1562.001 | Sysmon **1** / Security **4688** (cmdline) |
| 100140 | AS-REP Roasting — TGT sin preauth (`PreAuthType 0`) | T1558.004 | Security **4768** |
| 100150-152 | LOLBin de descarga (certutil / bitsadmin / mshta) | T1105 | Sysmon **1** (image + cmdline) |

> **Nota de tuning:** los nombres de campo `win.eventdata.*` se confirman contra el primer evento real decodificado
> (paso normal de afinado en Wazuh). El runbook incluye cómo verlos en *Security Events → ver evento crudo*.

---

## Hallazgos del lab que ya están reflejados aquí

- **Server 2025 emite AES (`0x12`), no RC4** → la detección fuerte de Kerberoasting es el **honeypot `svc_sql`**
  (cualquier 4769 hacia esa cuenta señuelo = malicioso, sin depender del cifrado). La regla RC4 queda como respaldo.
- **Sysmon (alta señal) y Security 4688 son complementarios** para cmdline → las reglas de tamper/LOLBin valen para ambos.
- **AS-REP** necesita un disparo real (KALI/Rubeus, diferido) para alerta end-to-end; la lógica ya está lista.

---

## Estado

- [x] SIEM decidido: **Wazuh** (self-hosted, offline)
- [x] Reglas del P3 portadas a Wazuh — `rules/local_rules.xml`
- [x] Config de ingesta (eventchannel) — `agent/windows-eventchannel.conf`
- [x] Runbook de despliegue — `deploy-wazuh-runbook.md`
- [ ] VM `WAZUH` creada e instalada (Ubuntu + Wazuh AIO)
- [ ] Agentes desplegados en DC01 / WIN11
- [ ] `local_rules.xml` cargado en el manager
- [ ] **Alerta real disparada** (re-ejecutar `../projects/03-detection-engineering/tests/Invoke-DetectionTests.ps1`)

---

## Qué demuestra este proyecto

Pipeline completo de **SIEM self-hosted**: ingesta multi-fuente (Sysmon + Windows Security + PowerShell),
**detección como código** (reglas Wazuh con mapeo MITRE ATT&CK), despliegue de agentes y validación
**atacando el propio lab** — todo en una red aislada, sin coste y sin depender de la nube.
