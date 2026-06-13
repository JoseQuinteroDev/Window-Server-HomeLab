# 🛰️ Microsoft Sentinel — despliegue del SIEM del lab

> Cierra la columna **Deploy & Monitor** del [Proyecto 3](../projects/03-detection-engineering/): subir nuestras
> detecciones (KQL) como **reglas analíticas** en Microsoft Sentinel y recibir alertas reales.

## ⚠️ Lo primero: la cuenta (lo haces tú, navegador)

Sentinel **corre sobre Azure**, así que lo imprescindible es una **suscripción Azure**. El tenant E5 es un extra (para Defender XDR).

1. **Tenant M365 E5 de desarrollador** (opcional pero recomendado, para Defender XDR):
   `https://developer.microsoft.com/microsoft-365/dev-program` → *Join* → crea el *sandbox* (E5, 25 licencias).
   > 🔸 **Aviso (cambio reciente):** Microsoft ahora puede exigir una **suscripción Visual Studio** para crear
   > nuevos sandboxes. Si no te deja, **no pasa nada para Sentinel** → usa solo el paso 2.

2. **Suscripción Azure** (IMPRESCINDIBLE para Sentinel):
   `https://azure.microsoft.com/free` → cuenta gratuita (crédito 200 USD / 30 días + 12 meses de servicios free).
   Úsala con la misma identidad que el tenant del paso 1 si lo creaste.
   > 💸 **Coste:** Sentinel tiene **31 días de prueba** (hasta ~10 GB/día gratis). El lab genera poquísimo log,
   > así que en la práctica es gratis. Aun así: **borra el resource group al terminar** para no acumular gasto.

3. Cuando tengas la suscripción, **inicia sesión** desde esta sesión de Claude Code escribiendo:
   ```
   ! az login
   ```
   (se abre el navegador; al volver, el token queda cacheado y yo despliego).

## Despliegue (lo hago yo, por script, tras tu `az login`)

```powershell
# 1) Crear RG + Log Analytics workspace + onboard Sentinel
.\deploy-sentinel.ps1 -ResourceGroup rg-soc-lab -Location westeurope -Workspace law-soc-lab

# 2) Desplegar las reglas analíticas (desde nuestro KQL del Proyecto 3)
az deployment group create -g rg-soc-lab `
  --template-file .\analytics-rules.json `
  --parameters workspaceName=law-soc-lab
```

## Conectar la telemetría del lab

El lab está **aislado**. Para que sus logs lleguen a Sentinel → ver [`connect-lab-runbook.md`](connect-lab-runbook.md)
(internet temporal + Azure Arc + Azure Monitor Agent + Data Collection Rules). Alternativa para endpoints:
onboarding a **Defender XDR** (MDE) y usar las variantes KQL `DeviceProcessEvents` de nuestras reglas.

## Estado

- [ ] Cuenta Azure (+ tenant E5) creada — *tú*
- [ ] `az login` hecho
- [ ] Workspace + Sentinel desplegados
- [ ] Reglas analíticas creadas
- [ ] Telemetría del lab conectada (Arc/AMA o Defender XDR)
- [ ] Alerta real disparada (re-ejecutar `Invoke-DetectionTests.ps1`)
