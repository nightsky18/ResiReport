# Práctica N.° 5: Auditoría y Remediación de Seguridad con Snyk CLI, MCP y GitHub Actions

**Aplicación al monorepo ResiReport (SAST, SCA y controles Shift-Left)**

* **Autora:** Mariana Montoya Sepúlveda

* **Institución:** Facultad de Ingenierías, Politécnico Colombiano Jaime Isaza Cadavid

* **Programa:** Diplomado en Ciberseguridad e Informática y Resiliencia Digital

* **Docente:** Edwin Andrés Ochoa Agudelo

* **Fecha:** Noviembre de 2026

## **Resumen**

Se documenta la auditoría práctica de seguridad de aplicaciones (SAST y SCA) ejecutada sobre el monorepo `ResiReport` (backend Node.js/Express y frontend React) utilizando Snyk CLI, el servidor MCP de Snyk integrado en Cursor IDE y flujos de integración continua en GitHub Actions. Los escaneos iniciales revelaron un total de 61 vulnerabilidades en dependencias (SCA) y 43 hallazgos en código fuente propietario (SAST). Con base en los criterios de priorización técnica, se seleccionaron, analizaron y remediaron tres vectores críticos: una denegación de servicio por expresiones regulares (ReDoS, CWE-400 / CWE-1333) en `residentController.js`; una deserialización de datos no confiables (CWE-502, CVE-2026-42211) vía dependencias transitivas en `react-router-dom`; y una contaminación de prototipos junto a división de respuestas HTTP (CVE-2026-42033 y CVE-2026-42035) en `axios`. La verificación posterior mediante re-escaneos demostró la extinción de los vectores evaluados en el código propio y la depuración de dependencias críticas directas. Asimismo, la implementación del Quality Gate en GitHub Actions validó la capacidad de interrupción automática del pipeline ante hallazgos de severidad alta residuales, consolidando una postura de seguridad proactiva bajo el paradigma *Shift-Left*.

**Palabras clave:** AppSec, SAST, SCA, Snyk CLI, MCP, Shift-Left, Quality Gate, ReDoS.

## **1. Introducción y Alcance de la Auditoría**

### **1.1 Introducción Técnica**

El desarrollo de software moderno se caracteriza por ciclos de entrega acelerados y una alta dependencia de componentes de terceros, bibliotecas de código abierto y herramientas de asistencia por inteligencia artificial. Este modelo operativo descentraliza el riesgo: el perímetro tradicional de red pierde vigencia frente a la superficie de ataque real constituida por las interfaces de programación de aplicaciones (APIs), la lógica de negocio y las vulnerabilidades heredadas en la cadena de suministro de software (*Software Supply Chain*).

En consonancia con los marcos de referencia de la industria (como OWASP Top 10 y el *Secure Software Development Framework* - SSDF del NIST), la disciplina de Seguridad de Aplicaciones (*AppSec*) ha evolucionado desde las auditorías de caja negra y las pruebas de penetración tardías hacia el enfoque *Shift-Left*. Dicho paradigma traslada los controles de seguridad hacia las etapas iniciales de codificación, integrando herramientas automatizadas de análisis estático de código fuente (SAST) y análisis de composición de software (SCA) directamente en el entorno de desarrollo local (IDE) y en los conductos de integración continua (CI/CD).

La presente práctica de laboratorio simula el rol operativo de un ingeniero de seguridad de aplicaciones (*AppSec Engineer*), aplicando el ciclo completo de gestión del riesgo: **detección, análisis de causa raíz, priorización contextual, remediación funcional, verificación empírica y prevención automatizada**.

### **1.2 Alcance y Reglas de Enfrentamiento**

El alcance de la auditoría se limitó estrictamente al repositorio local del monorepo full-stack `ResiReport`, estructurado bajo dos componentes principales:

* **`backend/`**: Servidor desarrollado en Node.js utilizando el framework Express.js, controladores de negocio, modelos de Mongoose/MongoDB y manifiesto de dependencias (`package.json`).

* **`frontend/`**: Aplicación de página única (*SPA*) desarrollada en React con Vite, enrutamiento mediante `react-router-dom` y gestión de peticiones HTTP con `axios`, respaldada por su respectivo `package.json` y `package-lock.json`.

**Reglas de seguridad operativa:**

1. Todas las pruebas de análisis y ejecución de comandos se restringieron exclusivamente al entorno de laboratorio controlado y autorizado en el monorepo local.

2. Quedó estrictamente prohibido el escaneo o ataque contra sistemas, direcciones IP o repositorios ajenos a la práctica.

3. Se protegió la confidencialidad de las credenciales: el token personal de autenticación (`SNYK_TOKEN`) se gestionó de forma exclusiva como variable de entorno local y como secreto en los repositorios remotos (`GitHub Secrets`), evitando su exposición en código fuente o registros públicos.

4. Las sugerencias de corrección generadas por modelos de lenguaje e IA (Cursor Agent / MCP) se sometieron a una rigurosa inspección humana obligatoria (*diff inspection*) antes de su aceptación e integración definitiva.

## **2. Metodología y Arquitectura de Auditoría**

La ejecución de la auditoría se basó en una arquitectura de tres capas que combina el motor CLI de Snyk, el protocolo de contexto de modelos (MCP) en el IDE y la automatización en la nube.

### **2.1 Configuración del Entorno y Autenticación del CLI**

Como paso fundacional, se estableció una identidad autenticada ante la plataforma SaaS de Snyk mediante la vinculación del token personal de la API (`SNYK_TOKEN`). La verificación de sesión se efectuó en la terminal ejecutando el comando de validación de identidad.

**Figura 1**
*Autenticación y validación de identidad en Snyk CLI*

![Autenticación del CLI de Snyk](screenshots/Pantallazo%201%20%28Autenticaci%C3%B3n%20del%20CLI%29.png)

*Nota.* Validación exitosa de la cuenta de usuario mediante el comando `snyk whoami` en la terminal de comandos.

### **2.2 Integración del Servidor MCP (Model Context Protocol) en Cursor IDE**

Para potenciar las capacidades de análisis y remediación asistida, se configuró el servidor Model Context Protocol de Snyk (`@snyk/mcp-server` / `snyk mcp`) dentro del entorno de desarrollo de Cursor IDE. Esta arquitectura permite que el agente de IA adquiera contexto directo de la base de datos de vulnerabilidades de Snyk en tiempo real, operando de manera integrada sobre el monorepo.

**Figura 2**
*Estado activo del servidor MCP de Snyk en Cursor IDE*

![Servidor MCP de Snyk activo en Cursor](screenshots/Pantallazo%202%20%28Servidor%20MCP%20en%20Cursor%29.png)

*Nota.* Panel de administración de MCPs en Cursor mostrando el servidor conectado con indicador verde y 14 herramientas habilitadas para el proyecto.

### **2.3 Ejecución de Escaneos de Línea Base (SCA y SAST)**

Se realizaron los escaneos iniciales para inventariar la postura de seguridad global del proyecto:

1. **Análisis de Composición de Software (SCA):** Mediante `snyk test --all-projects`, evaluando tanto las dependencias directas como transitivas de los manifiestos del frontend, backend y la raíz.

2. **Análisis Estático de Código (SAST):** Mediante `snyk code test`, examinando los flujos de datos en el código fuente propietario en busca de patrones vulnerables.

**Figura 3**
*Resultados globales del escaneo SCA en ResiReport*

![Resultados SCA completos](screenshots/Pantallazo%203%20%28Resultados%20SCA%20completos.png)

*Nota.* Salida del CLI detallando 61 vulnerabilidades abiertas en todo el monorepo (5 críticas, 19 altas, 36 medias y 1 baja).

**Figura 4**
*Filtrado de vulnerabilidades SCA por umbral de severidad Alta y Crítica*

![Filtrado de severidad alta y crítica](screenshots/Pantallazo%204%20%28Filtrado%20de%20severidad%20alta%20-cr%C3%ADtica%29.png)

*Nota.* Ejecución de `snyk test --severity-threshold=high` aislando los riesgos prioritarios.

**Figura 5**
*Resultados del escaneo SAST de código propietario*

![Resultados SAST](screenshots/Pantallazo%205%20%28Resultados%20SAST%29.png)

*Nota.* Hallazgos estáticos reportados por Snyk Code, destacando vulnerabilidades de denegación de servicio (ReDoS) en controladores de residentes y catálogos.

## **3. Matriz de Vulnerabilidades Auditadas**

De acuerdo con las directrices metodológicas, se seleccionaron tres vulnerabilidades representativas (una SAST en código propio y dos SCA en componentes de terceros) para documentar su ciclo completo de tratamiento.

**Tabla 1**
*Matriz obligatoria de vulnerabilidades seleccionadas en ResiReport*

| N.° | Hallazgo | Tipo | CVE / CWE | Severidad | CVSS v3.1 | Activo Afectado | Estado | 
| ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | 
| **1** | Regular Expression Denial of Service (ReDoS) | SAST | CWE-400 / CWE-1333 | Alta | 7.5 (Est.) | `backend/src/controllers/residentController.js` (Líneas 77–85) | **Corregido** | 
| **2** | Deserialization of Untrusted Data | SCA | CVE-2026-42211 / CWE-502 | Crítica | 9.1 | `frontend/package.json` (`react-router-dom@7.13.1` > `react-router@7.13.1`) | **Corregido** | 
| **3** | Prototype Pollution & HTTP Response Splitting | SCA | CVE-2026-42033 / CVE-2026-42035 | Crítica | 9.1 | `frontend/package.json` (`axios@1.13.6`) | **Corregido** | 

*Nota.* Elaboración propia. La puntuación CVSS de la vulnerabilidad SAST constituye una estimación técnica basada en el impacto de disponibilidad sobre endpoints expuestos.

## **4. Fichas Técnicas y Análisis Profundo de Remediación**

### **4.1 Vulnerabilidad 1: Regular Expression Denial of Service (ReDoS) — SAST**

#### **Ficha Técnica y Métricas**

* **Nombre:** Regular Expression Denial of Service (ReDoS)

* **Identificador y Tipo:** Snyk Code Rule `javascript/reDOS` (SAST)

* **CWE:** CWE-400 (Uncontrolled Resource Consumption) y CWE-1333 (Inefficient Regular Expression Complexity)

* **Severidad:** Alta | **CVSS v3.1:** 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)

* **Ubicación:** `backend/src/controllers/residentController.js`, líneas 77–85.

#### **Análisis de Riesgo e Impacto CID**

* **Confidencialidad:** Nula o baja (funciona como oráculo lógico para verificar existencia de registros).

* **Integridad:** Media (permite la alteración lógica de la unicidad en las búsquedas de residentes si se introducen comodines maliciosos).

* **Disponibilidad:** **Alta**. Al permitir que entradas controladas por el usuario se compilen directamente en expresiones regulares, un atacante puede suministrar cadenas con alta ambigüedad de backtracking, colapsando el *Event Loop* de Node.js y negando el servicio a usuarios legítimos.

#### **Causa Raíz**

El código original interpolaba directamente los parámetros `torre` y `apartamento` (provenientes del cuerpo de la petición HTTP) dentro de constructores `new RegExp()`. Esto constituye un defecto de implementación donde datos no confiables se interpretan como sintaxis de expresiones regulares en lugar de texto literal.

**Código ANTES (Vulnerable):**

```
const aptExists = await User.findOne({
  rol: 'resident',
  torre: { $regex: new RegExp(`^${torre.trim()}$`, 'i') },
  apartamento: { $regex: new RegExp(`^${apartamento.trim()}$`, 'i') },
});

```

#### **Proceso de Remediación Asistida (Cursor Agent + MCP)**

Utilizando la integración con el servidor MCP de Snyk, el agente analizó el repositorio, localizó el sumidero vulnerable y propuso una función auxiliar de escape para neutralizar los metacaracteres RegExp.

**Figura 6**
*Interacción con Cursor Agent invocando herramientas MCP de Snyk*

![(a) Prompt y uso de herramientas Snyk](screenshots/Pantallazo%206%20%28Prompt%20e%20Interacci%C3%B3n%20MCP%29/Utilizando%20herramientas%20snyk.png)

![(b) Autenticación del servidor MCP](screenshots/Pantallazo%206%20%28Prompt%20e%20Interacci%C3%B3n%20MCP%29/mcp.png)

![(c) Confirmación del ReDoS por Snyk](screenshots/Pantallazo%206%20%28Prompt%20e%20Interacci%C3%B3n%20MCP%29/Confirmaci%C3%B3n%20ReDoS.png)

*Nota.* (a) Composer mostrando el prompt y el razonamiento del agente; (b) autenticación exitosa del servidor MCP de Snyk; (c) confirmación del ReDoS en `torre` y `apartamento` por parte de Snyk.

**Código DESPUÉS (Corregido):**

```
// Neutraliza metacaracteres antes de interpolar entrada de usuario en un RegExp.
const escapeRegExp = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const torreExacta = escapeRegExp(torre.trim());
const apartamentoExacto = escapeRegExp(apartamento.trim());

const aptExists = await User.findOne({
  rol: 'resident',
  torre: { $regex: new RegExp(`^${torreExacta}$`, 'i') },
  apartamento: { $regex: new RegExp(`^${apartamentoExacto}$`, 'i') },
});

```

**Figura 7**
*Inspección del Diff antes de aceptar los cambios propuestos*

![Diff de código ANTES y DESPUÉS](screenshots/Pantallazo%207%20%28Diff%20de%20C%C3%B3digo%20ANTES%20-DESPU%C3%89S%29.png)

*Nota.* Vista comparativa (*diff*) en Cursor IDE evidenciando la inserción de `escapeRegExp` y la sanitización de los parámetros.

#### **Verificación por Re-escaneo SAST**

Tras aplicar el parche, se reejecutó el análisis estático de código.

**Figura 8**
*Re-escaneo SAST confirmando la eliminación del ReDoS en el controlador*

![Re-escaneo SAST](screenshots/Pantallazo%208%20%28Re-escaneo%20SAST%29%20.png)

*Nota.* Salida de terminal con la reducción de hallazgos altos de 9 a 7, extinguiendo los avisos en `residentController.js`.

### **4.2 Vulnerabilidades SCA: `react-router-dom` y `axios`**

#### **Fichas Técnicas y Causa Raíz**

* **Vulnerabilidad 2 (`react-router-dom`):** Deserialización insegura de datos no confiables (`CVE-2026-42211`, CWE-502). Presente en la versión `7.13.1` (transitiva a través de `react-router`), con severidad **Crítica** (CVSS 9.1).

* **Vulnerabilidad 3 (`axios`):** Contaminación de prototipos (`CVE-2026-42033`) y división de respuestas HTTP (`CVE-2026-42035`). Presente en la versión directa `1.13.6`, con severidad **Crítica** (CVSS 9.1).

#### **Remediación Aplicada**

Se actualizaron los manifiestos de dependencias del frontend (`frontend/package.json` y `frontend/package-lock.json`) elevando las versiones estables seguras recomendadas:

* `axios`: de `^1.13.6` a `^1.15.2`

* `react-router-dom`: de `^7.13.1` a `^7.14.2`

**Figura 9**
*Re-escaneo SCA del frontend tras aplicar la actualización de paquetes*

![Re-escaneo SCA](screenshots/Pantallazo%209%20%28Re-escaneo%20SCA%29.png)

*Nota.* Comprobación en terminal reportando 0 vulnerabilidades abiertas en el árbol de dependencias directas analizado del frontend.

## **5. Estrategia Preventiva y Controles Shift-Left**

Para mitigar la reintroducción de vulnerabilidades y automatizar la gobernanza, se configuraron dos barreras preventivas.

### **5.1 Guardrailes en el IDE (`.cursorrules`)**

Se estableció un archivo de directivas en la raíz del entorno de desarrollo para condicionar el comportamiento del agente de IA al generar código.

**Figura 10**
*Archivo de reglas de desarrollo seguro para el agente*

![Reglas del IDE (.cursorrules)](screenshots/Pantallazo%2010%20%28Reglas%20del%20IDE%29.png)

*Nota.* Definición de políticas para evitar patrones ReDoS y requerir validación estricta de entradas.

### **5.2 Quality Gate en CI/CD (GitHub Actions)**

Se configuró un flujo automatizado de integración continua que ejecuta escaneos estrictos de Snyk en cada evento de *push* o *pull request* hacia la rama principal.

**Figura 11**
*Definición del pipeline de control en GitHub Actions*

![Workflow de GitHub Actions](screenshots/Pantallazo%2011%20%28Workflow%20de%20GitHub%20Actions%29.png)

*Nota.* Script YAML configurado en `.github/workflows/security-gate.yml` con el umbral `--severity-threshold=high`.

**Figura 12**
*Ejecución y bloqueo efectivo del Quality Gate en la plataforma de GitHub*

![(a) Pipeline bloqueado](screenshots/Pantallazo%2012%20%28Quality%20Gate%20Ejecutado%20-%20Bloqueo%29/Bloqueo.png)

![(b) Resultado del escaneo en el pipeline](screenshots/Pantallazo%2012%20%28Quality%20Gate%20Ejecutado%20-%20Bloqueo%29/Resultado.png)

*Nota.* (a) Ejecución fallida del workflow `security-gate.yml`; (b) detalle del resultado. Demostración del bloqueo del pipeline (`exit code 1`) al persistir 4 vulnerabilidades de severidad alta transitivas en `react-router-dom@7.14.2`, evidenciando el funcionamiento correcto de la política de seguridad.

## **6. Respuestas Fundamentadas a las Preguntas de Cierre**

Estas respuestas parten de lo que observé en la práctica: los resultados de los escaneos, los reescaneos y la ejecución real del Quality Gate. Donde la herramienta no entregó un dato, por ejemplo la alcanzabilidad de las dependencias, lo digo de forma explícita y no lo doy por supuesto.

### **6.1 ¿Cuál de las tres vulnerabilidades representa mayor riesgo real y por qué?**

Para mí, el mayor riesgo real lo tiene el **ReDoS de `residentController.js`**, aunque su puntuación (7.5 estimada) sea menor que la de las otras dos (9.1). Es la única de las tres con un flujo confirmado por Snyk Code: el dato entra por el cuerpo de la petición HTTP, llega sin sanitizar a `new RegExp()` y se ejecuta en un endpoint de la propia API. Además, es código propio, así que no depende de que un tercero publique un parche.

Las vulnerabilidades de `react-router` y `axios` son críticas, pero su explotación exige otras condiciones: que la aplicación procese datos serializados controlados por un atacante, o que datos no confiables lleguen a la configuración o a las cabeceras de las peticiones. Si la ruta de registro exigiera un rol administrativo, el riesgo bajaría, ese control de acceso no lo evalué en esta práctica.

### **6.2 ¿La mayor puntuación CVSS siempre debe corregirse primero?**

No. El CVSS describe la severidad técnica intrínseca de una vulnerabilidad, pero no dice nada sobre el entorno concreto donde vive (FIRST, 2019). Para priorizar hay que sumarle otras preguntas: si el componente es alcanzable desde el código de la aplicación, si el activo está expuesto, si existe un exploit maduro y qué tan probable es que alguien lo use.

La Tabla 1 lo muestra bien. Dos hallazgos con CVSS 9.1 quedaron con un riesgo real medio, mientras que el ReDoS, con un puntaje menor, quedó como el más urgente. Un hallazgo alto y alcanzable puede merecer más prioridad que uno crítico en una función que la aplicación nunca invoca.

### **6.3 ¿Qué diferencia hay entre vulnerabilidad identificada y vulnerabilidad explotable?**

Una vulnerabilidad **identificada** es un defecto que aparece en el código o en una versión de paquete listada en una base de datos como la de Snyk. Es, por decirlo así, un riesgo latente.

Una vulnerabilidad **explotable** necesita además tres cosas: una entrada que el atacante pueda controlar, una ruta de ejecución que llegue hasta el componente defectuoso y las condiciones de acceso que lo permitan. Por eso en el informe valoro el riesgo real por separado de la severidad, y dejo como "no determinada" la alcanzabilidad de las dependencias, porque Snyk CLI no la reportó.

### **6.4 ¿Qué impacto tiene sobre la tríada CID?**

Cada hallazgo toca la tríada de forma distinta:

* **Disponibilidad:** el ReDoS es el caso más claro. Un patrón malicioso puede saturar la CPU y dejar sin servicio el registro de residentes.
* **Integridad:** el ReDoS altera de forma lógica la comprobación de unicidad si se cuelan comodines. La deserialización en `react-router` puede alterar el estado del cliente, y la contaminación de prototipos en `axios` puede modificar silenciosamente la configuración de las peticiones.
* **Confidencialidad:** el impacto es bajo en el ReDoS, aunque la respuesta de la comprobación funciona como oráculo para saber qué combinaciones de torre y apartamento ya existen. En `axios`, la manipulación de cabeceras podría exponer credenciales como tokens de sesión.

### **6.5 ¿Qué control habría detectado el problema antes de producción?**

Un análisis estático en el IDE, con Snyk Code o una regla de ESLint/Semgrep, habría marcado el ReDoS en el momento de escribirlo. El análisis de composición de software (SCA) habría señalado las dependencias vulnerables al incorporarlas al proyecto. Ambos controles corresponden a las prácticas de revisión de código y de identificación continua de vulnerabilidades del marco del NIST (Souppaya et al., 2022). Un *hook* de *pre-commit* añadiría una barrera más, local, antes de que el cambio llegue al repositorio.

### **6.6 ¿Cómo llevaría ese control al CI/CD?**

Con un Quality Gate como el de `security-gate.yml`. El escáner devuelve un código de salida distinto de cero cuando encuentra hallazgos por encima del umbral, el trabajo falla y, si la rama está protegida con verificaciones obligatorias, se bloquea la fusión (GitHub, s. f.).

En la práctica ocurrió exactamente eso: la ejecución terminó en *Failure* con `exit code 1` por cuatro hallazgos altos residuales en `react-router-dom@7.14.2`, y Snyk recomendó actualizar a la versión `7.18.0` (Figura 12). Para llevarlo a producción haría falta, además, definir cómo gestionar las excepciones aceptadas, por ejemplo con exenciones documentadas y con fecha de caducidad.

### **6.7 ¿Qué limitaciones se observaron en la automatización y qué parte requiere criterio humano?**

La automatización fue muy buena para descubrir hallazgos en masa y para proponer en segundos un parche sintácticamente correcto. Pero le vi límites concretos:

* No reportó la alcanzabilidad de las dependencias.
* Necesitó instalar `node_modules` para poder escanear el frontend (Figura 6).
* Los reescaneos con filtro de severidad ocultan los hallazgos de menor nivel, así que el estado de dependencias transitivas como `follow-redirects` o `form-data` hay que confirmarlo con un `snyk test` sin filtro.
* El agente no puede juzgar si un parche cambia la experiencia esperada ni si una ruta está realmente protegida.

Todo eso le corresponde al auditor: revisar el diff, validar la lógica de negocio, correr pruebas de regresión, poner el riesgo en contexto y decidir las excepciones. Es lo que plantea la guía de la práctica cuando dice que la IA no sustituye el criterio del auditor (Politécnico Colombiano Jaime Isaza Cadavid, 2026b).


## **7. Conclusiones y Trabajo Futuro**

* La auditoría permitió identificar y erradicar con éxito fallos críticos tanto en el código fuente propietario como en la cadena de suministro de dependencias del monorepo `ResiReport`.

* El uso coordinado de Snyk CLI y el servidor MCP en Cursor IDE demostró una reducción drástica en el tiempo medio de triaje y remediación (*MTTR*).

* El comportamiento del Quality Gate en GitHub Actions ratificó que la automatización de la seguridad en CI/CD actúa como un mecanismo de defensa robusto para impedir que componentes con riesgos altos alcancen los entornos productivos.

* **Trabajo futuro:** Se recomienda actualizar `react-router-dom` a la versión `7.18.0` para solventar los remanentes altos detectados por el pipeline, implementar validaciones mediante esquemas estrictos (Zod) en los controladores del backend, y extender los controles Shift-Left a ganchos de pre-commit locales.

## **8. Referencias Bibliográficas**

* Anthropic. (2024). *Introducing the Model Context Protocol*. https://www.anthropic.com/news/model-context-protocol

* First.org. (2019). *Common Vulnerability Scoring System version 3.1: Specification Document*. https://www.first.org/cvss/v3.1/specification-document

* GitHub. (s. f.). *GitHub Actions Documentation*. Recuperado el 3 de noviembre de 2026, de https://docs.github.com/en/actions

* OWASP Foundation. (2021). *OWASP Top 10:2021*. https://owasp.org/Top10/

* Politécnico Colombiano Jaime Isaza Cadavid. (2026a). *Auditoría de seguridad de aplicaciones y gestión continua del riesgo* \[Material de clase\]. Diplomado en Ciberseguridad.

* Politécnico Colombiano Jaime Isaza Cadavid. (2026b). *Implementación práctica: Snyk, CLI* (Guía de práctica N.° 5, código FD-GC195). Facultad de Ingenierías.

* Politécnico Colombiano Jaime Isaza Cadavid. (2026c). *Implementación práctica: Snyk, CLI y MCP en Cursor* \[Material de clase\]. Diplomado en Ciberseguridad.

* Snyk. (s. f.). *Snyk Vulnerability Database & CLI Documentation*. Recuperado el 3 de noviembre de 2026, de https://security.snyk.io/

* Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure software development framework (SSDF) version 1.1* (NIST SP 800-218). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218
