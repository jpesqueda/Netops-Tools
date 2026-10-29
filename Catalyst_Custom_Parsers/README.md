# Catalyst Custom Parsers — paquete inicial v1.0

**Objetivo:** complementar la generación de Excel del proyecto Catalyst Config Auditor con parsing offline para **nueve comandos** que se identificaron como pendientes. No modifica la versión actual del auditor ni requiere conectarse al equipo.

## Inventario de templates

| Comando | Archivo | Campos / alcance |
|---|---|---|
| `show environment all` | `TextFSM/cisco_ios_show_environment_all.textfsm` | FAN, fuentes de alimentación y temperatura (subconjunto) |
| `show interfaces counters` | `TextFSM/cisco_ios_show_interfaces_counters.textfsm` | Octetos, unicast, multicast y broadcast, IN/OUT |
| `show interfaces counters errors` | `TextFSM/cisco_ios_show_interfaces_counters_errors.textfsm` | Align/FCS/Xmit/Rcv/UnderSize/OutDiscards |
| `show interfaces trunk` | `TextFSM/cisco_ios_show_interfaces_trunk.textfsm` | Status, native VLAN, allowed, active, forwarding |
| `show ip arp inspection interfaces` | `TextFSM/cisco_ios_show_ip_arp_inspection_interfaces.textfsm` | Interface, trust, rate y burst cuando aparezca |
| `show ip protocols` | `TextFSM/cisco_ios_show_ip_protocols.textfsm` | Protocol, redistribute, networks y distance **parcial** |
| `show ip dhcp snooping` | `TextFSM/cisco_ios_show_ip_dhcp_snooping.textfsm` | Estado global, VLANs, Option 82, interfaces |
| `show device-tracking database` | `TextFSM/cisco_ios_show_device-tracking_database.textfsm` | IPv4, MAC, VLAN, interface y state (formatos comunes) |
| `show running-config` | `TTP/cisco_ios_show_running-config.ttp` | **Solo extracción selectiva** de hostname, interfaces y BGP; mantener `--vars` para la configuración completa |

**Importante:** estos templates se diseñaron para ejemplos comunes de Cisco Catalyst IOS-XE. No representan cobertura universal de todas las versiones ni de todos los formatos de cada comando. Algunos outputs tienen variantes por plataforma, versión y configuración.

## Estructura

```text
Catalyst_Custom_Parsers_v1.0/
├── TextFSM/
│   ├── index
│   └── cisco_ios_*.textfsm      (8 archivos)
├── TTP/
│   └── cisco_ios_show_running-config.ttp
├── fixtures/
│   └── show_*.txt               (9 ejemplos sintéticos)
├── tools/
│   ├── parse_custom.py
│   └── syntax_check.py
├── requirements.txt
├── manifest.json
└── README.md
```

## Instalación en Windows

```powershell
py -m pip install textfsm ttp
```

- `textfsm` es necesario para los ocho parsers de salida CLI.
- `ttp` es necesario **solo** para el ejemplo selectivo de `show running-config`.
- La utilidad `parse_custom.py` usa exclusivamente archivos locales.

## Probar los templates

Comprueba sintaxis de expresiones regulares (sin dependencias externas):

```powershell
python tools/syntax_check.py
```

Pruebas reales con los motores TextFSM/TTP instalados:

```powershell
python tools/parse_custom.py --test-all
```

Probar un archivo real o sintético previamente guardado:

```powershell
python tools/parse_custom.py --command "show interfaces trunk" --input fixtures/show_interfaces_trunk.txt --output trunk.csv
python tools/parse_custom.py --command "show interfaces counters" --input fixtures/show_interfaces_counters.txt --output counters.csv
python tools/parse_custom.py --command "show running-config" --input fixtures/show_running-config.txt --output extracted.json
```

`trunk.csv` tendrá una fila por puerto con campos como `PORT`, `NATIVE_VLAN`, `ALLOWED_VLANS`, `ACTIVE_VLANS`, `FORWARDING_VLANS`. `counters.csv` agrupa los bloques IN/OUT por puerto. **La agrupación está en el helper Python, no es una función nativa de TextFSM**.

Si un parser no obtiene registros, el helper devuelve error; no trata resultados vacíos como éxito. En futuras integraciones a Excel, se debe guardar **RAW** si falla el parsing o la validación de cobertura.

## Cómo integrarlo con Catalyst Config Auditor

El `Catalyst_Config_Auditor.py` v1.3.5 **no carga automáticamente estos archivos**. Hay que agregar un selector de parsers al módulo de Excel o usar `tools/parse_custom.py` offline como etapa previa. La idea es:

```text
Commands_Output.txt / salida guardada
              ↓
  parser personalizado TextFSM
              ↓ (sin coincidencias)
       NTC Templates
              ↓ (sin coincidencias)
       parser Python actual
              ↓ (sin coincidencias)
              RAW
              ↓
         Excel por switch
```

`TextFSM/index` es un índice **para este directorio personalizado**, usando el formato NTC. Si deseas utilizar a la vez la colección NTC instalada, no reemplaces su índice global por este archivo sin combinar las referencias; es preferible que el script pruebe primero los templates personalizados por ruta y después use NTC para los restantes.

## Consideraciones de calidad

- En `show interfaces counters`, TextFSM devuelve registros separados por bloque. `tools/parse_custom.py` los agrupa por `PORT`. El mismo método agrupa los cuatro bloques de `show interfaces trunk`.
- `show environment all` tiene salidas muy distintas en 9300, 9400 y 9500. El template incluido captura algunos estados habituales; cualquier sección no reconocida debe conservarse en RAW.
- `show ip protocols` es jerárquico; este TextFSM captura un subconjunto. Para más detalle es preferible crear un template TTP por protocolo (OSPF/EIGRP/BGP).
- `show device-tracking database` presenta formatos diferentes según `device-tracking` / SISF y la versión IOS-XE; ajustar usando fixtures propios.
- **No conviertas un `show running-config` completo a una tabla**: el template TTP es una muestra de extracción limitada. Para tu proyecto de YAML/Jinja2 conserva el parser de `--vars` y el backup original.
- No guardes contraseñas o secretos en fixtures, reportes públicos o repositorios Git. Los ejemplos usan direcciones del bloque de documentación `192.0.2.0/24` y valores ficticios.
- Cuando incorpores outputs reales, prueba en cada familia 9300/9400/9500 y en diferentes releases. Mantén un caso `.txt` y el resultado esperado para cada variante.

## Estado de validación

- **Realizado en este entorno:** compilación de las expresiones regulares y detección de coincidencias en los ocho fixtures TextFSM sintéticos.
- **No realizado aquí:** ejecución contra la biblioteca TextFSM/TTP (no está disponible para instalarse en el entorno aislado) ni pruebas contra equipos reales.
- Ejecuta `--test-all` en Windows después de instalar dependencias para confirmar el comportamiento del motor y adaptar los casos que lo requieran.

Fuentes de referencia de formato: [NTC developer guide](https://github.com/networktocode/ntc-templates/blob/master/docs/dev/dev_parser.md), [NTC index](https://github.com/networktocode/ntc-templates/blob/master/ntc_templates/templates/index), documentación Cisco Catalyst IOS-XE.
