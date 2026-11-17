#evtx-hunting-writeup

Caza de amenazas ("threat hunting") sobre logs de Windows usando **Chainsaw** + reglas **Sigma**, con un writeup de tres ataques reales de laboratorio: qué técnica es, qué evento la delata y qué haría un analista después.

No hace falta montar ninguna máquina virtual: las muestras son ficheros `.evtx` públicos que se analizan offline.

## Resultado en una línea

Sobre las **150 muestras con detecciones** del dataset EVTX-ATTACK-SAMPLES, Chainsaw (reglas Sigma + reglas propias, solo severidad *high/critical*) generó **549 detecciones**. Resumen completo: [`examples/resumen_detecciones.md`](examples/resumen_detecciones.md).

## Herramientas y versiones

| Pieza | Versión usada |
|---|---|
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | v2.17.1 |
| [Reglas Sigma](https://github.com/SigmaHQ/sigma) (`rules/windows`) | commit `05d1031` |
| [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | commit `4ceed2f` |

> Las reglas Sigma cambian a menudo: con otra versión los números pueden variar.

## Cómo reproducirlo

```bash
git clone https://github.com/IvanVH909/evtx-hunting-writeup
cd evtx-hunting-writeup
scripts/setup.sh        # descarga muestras, reglas Sigma y Chainsaw en ./lab (Linux x86_64)
scripts/run_hunt.sh     # ejecuta la caza y genera results/hunt.jsonl + results/resumen.md
```

El comando de fondo es:

```bash
chainsaw hunt evtx/ -s sigma/rules/windows -r chainsaw/rules \
  --mapping chainsaw/mappings/sigma-event-logs-all.yml \
  --level high --level critical --skip-errors --jsonl -o hunt.jsonl
```

(En macOS/Windows usa el binario de tu plataforma desde la página de *releases* de Chainsaw.)

## Tabla resumen: técnica → ATT&CK → evidencia

| Caso | Técnica | ATT&CK | Evento que la delata |
|---|---|---|---|
| 1. Volcado de LSASS | Robo de credenciales de memoria | T1003.001 | Sysmon 10 (acceso a `lsass.exe` con `0x1fffff`) + Sysmon 11 (fichero `.dmp`) |
| 2. Servicio remoto con PowerShell ofuscado | Ejecución vía servicio (estilo PsExec/Meterpreter) | T1569.002, T1059.001, T1027 | Sysmon 13 (`ImagePath` de un servicio nuevo) + Sysmon 1 (cadena de procesos) |
| 3. Borrado de logs y cambio de ACL del dominio | Borrado de evidencias + permisos DCSync | T1070.001 · T1098 (→ T1003.006) | Security 1102 + Security 5136 |

---

## Caso 1 — Volcado de memoria de LSASS

**Fichero:** `Credential Access/sysmon_10_11_lsass_memdump.evtx` · **Equipo:** `PC04.example.corp`

Reglas que saltaron (5 detecciones, todas *high*): *LSASS Memory Access by Tool With Dump Keyword In Name*, *Suspicious Process Access to LSASS with Dbgcore/Dbghelp DLLs*, *LSASS Process Memory Dump Files* (x2) y *LSASS Process Memory Dump Creation Via Taskmgr.EXE*.

**Qué pasó (UTC):**

- `19:09:41` — Sysmon **EID 10**: `C:\Users\IEUser\Desktop\procdump.exe` abre `C:\Windows\system32\lsass.exe` con `GrantedAccess = 0x1fffff` (acceso total al proceso). La pila de llamadas (`CallTrace`) pasa por `ntdll`/`kernel32`.
- `19:09:41` — Sysmon **EID 11**: se crea `C:\Users\IEUser\Desktop\lsass.exe_190317_120941.dmp`.
- `19:10:03` — Sysmon **EID 11**: `taskmgr.exe` crea `C:\Users\IEUser\AppData\Local\Temp\lsass (2).DMP`: es la segunda técnica (volcado desde el Administrador de tareas).

**Por qué es sospechoso:** `lsass.exe` guarda credenciales en memoria; un proceso de usuario que lo abre con acceso total y escribe un `.dmp` encaja con el robo de credenciales. Que haya **dos** métodos distintos en 22 segundos refuerza la sospecha.

**Qué haría un analista después:**

1. Aislar el equipo y conservar el `.dmp` como evidencia (hash incluido).
2. Asumir comprometidas las credenciales de las sesiones activas en `PC04` y forzar cambio de contraseña.
3. Buscar en el resto de la red el mismo hash de `procdump.exe` y accesos a LSASS desde otros equipos.
4. Mitigación: activar *LSA Protection* / Credential Guard y regla ASR de bloqueo de robo de credenciales de LSASS.

---

## Caso 2 — Servicio remoto que lanza PowerShell ofuscado

**Fichero:** `Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx` · **Equipo:** `IEWIN7`

Reglas que saltaron (11 detecciones): *Potential CobaltStrike Service Installations - Registry*, *PowerShell as a Service in Registry*, *Suspicious SYSTEM User Process Creation* (x3), *Abused Debug Privilege by Arbitrary Parent Processes*, *Base64 Encoded PowerShell Command Detected* (x3) y *Potential PowerShell Command Line Obfuscation* (x2).

**Qué pasó (UTC, 2019-04-30):**

- `20:26:51` — Sysmon **EID 13**: `services.exe` escribe `HKLM\System\CurrentControlSet\services\hello\ImagePath` con el valor `%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -noni -c "..."`. Se ha registrado un **servicio nuevo llamado `hello`** cuyo "ejecutable" es una línea de PowerShell.
- `20:26:52` — Sysmon **EID 1**: cadena de procesos `services.exe → cmd.exe → powershell.exe → powershell.exe`, todos como `NT AUTHORITY\SYSTEM`.
- Los parámetros `-nop -w hidden -noni` (sin perfil, ventana oculta, no interactivo) y un bloque comprimido con GZip y codificado en Base64 son típicos de *payloads* de Metasploit y similares.

**Por qué es sospechoso:** un servicio legítimo apunta a un binario; uno cuyo `ImagePath` es una línea de comandos con PowerShell oculto y *payload* codificado es la huella del movimiento lateral estilo PsExec (T1569.002 sobre SMB, T1021.002).

**Qué haría un analista después:**

1. Revisar el log de sistema (evento 7045, instalación de servicio) y el de seguridad (4624 tipo 3, 5140/5145 para SMB) para saber **desde qué IP y con qué cuenta** llegó.
2. Decodificar el *payload* (Base64 → GZip) en un entorno aislado para ver qué hace y a qué dirección conecta.
3. Eliminar el servicio, aislar el equipo y revisar otras máquinas por servicios con el mismo nombre.
4. Mitigación: restringir administración remota por SMB, desactivar la cuenta usada y registrar PowerShell (ScriptBlock Logging).

---

## Caso 3 — Borrado de logs y cambio de permisos en el dominio (DCSync)

**Fichero:** `Persistence/DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl.evtx` · **Equipo:** `DC1.insecurebank.local`

Reglas que saltaron (19 detecciones): *Security Audit Logs Cleared* (critical, x1) y *Powerview Add-DomainObjectAcl DCSync AD Extend Right* (high, x18).

**Qué pasó (UTC, 2019-03-25):**

- `21:28:11` — Security **EID 1102**: el usuario `bob` **borra el registro de seguridad** del controlador de dominio.
- `21:28:45` — Security **EID 5136**: el mismo usuario `bob` modifica el atributo `nTSecurityDescriptor` del objeto `DC=insecurebank,DC=local` (el propio dominio). La regla lo asocia con `Add-DomainObjectAcl` de PowerView para conceder derechos de replicación de directorio (DCSync).

**Por qué es sospechoso:** borrar el log de un controlador de dominio es una maniobra para ocultar rastros (T1070.001), y tocar la ACL del dominio es persistencia con privilegios (T1098). Conceder derechos de replicación permite después volcar los hashes de todo el dominio con un DCSync (T1003.006).

**Qué haría un analista después:**

1. Tratarlo como incidente crítico: `bob` no debería poder hacer ninguna de las dos cosas. Deshabilitar la cuenta y revisar cómo obtuvo esos privilegios.
2. Listar quién tiene hoy los permisos *Replicating Directory Changes* sobre el dominio y revertir los no autorizados.
3. Recuperar los eventos borrados desde el SIEM / reenvío de eventos (por eso es clave tener los logs centralizados).
4. Si hubo DCSync, rotar `krbtgt` (dos veces) y las credenciales privilegiadas.

> Nota de honestidad: el dataset es de laboratorio y cada fichero contiene un ataque aislado. En un entorno real habría mucho más ruido.

---

## Falsos positivos y ruido

Un resultado de Chainsaw es una **pista**, no un veredicto. En esta ejecución, por ejemplo, la regla *User Authentication Succeeded* aparece como *critical* 11 veces solo porque el fichero muestra un inicio de sesión exitoso en un escenario de túnel RDP: sin contexto no es malicioso por sí mismo. Siempre hay que correlacionar con el resto de eventos.

## Limitaciones y siguientes pasos

- Solo se han revisado las detecciones *high/critical*; las de severidad media/baja podrían aportar contexto.
- Idea: añadir un script que cruce 1102/5136 con 4624 para sacar la cuenta y la IP de origen.
- Idea: convertir las detecciones en una línea temporal por equipo.

## Créditos

- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) por @sbousseaden (GPL-3.0). Las muestras **no** se incluyen en este repo.
- [Chainsaw](https://github.com/WithSecureLabs/chainsaw) (WithSecure Labs) y [Sigma](https://github.com/SigmaHQ/sigma).
