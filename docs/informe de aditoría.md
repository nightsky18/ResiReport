# SECURITY_LAB_REPORT.md

## **1. Portada Técnica**

* **Título del Entregable:** Informe Final de Auditoría y Remediación de Seguridad (Práctica 5)

* **Proyecto Auditado:** `ResiReport` (Estructura Monorepo Full-Stack)

* **Autora:** Mariana Montoya Sepúlveda

* **Perfil Profesional:** Estudiante de Ingeniería Informática / Diplomado en Ciberseguridad

* **Herramientas de Auditoría y Control:** Snyk CLI, Snyk MCP Server, Cursor IDE, GitHub Actions

* **Fecha de Evaluación:** Noviembre de 2026

## **2. Resumen Ejecutivo**

Se realizó una auditoría de seguridad integral (SAST y SCA) sobre el repositorio `ResiReport`. Inicialmente se identificaron **61 vulnerabilidades en dependencias (SCA)** y **43 hallazgos en código fuente propietario (SAST)**.

A través del ciclo de remediación asistida con Cursor Agent e integración MCP de Snyk, se neutralizaron los vectores de riesgo de severidad Alta y Crítica. En el código propio se eliminó la amenaza de Denegación de Servicio por Expresiones Regulares (ReDoS) en controladores del backend, y en el frontend se redujeron a **0 los hallazgos críticos en dependencias directas**. Asimismo, se implementaron controles preventivos Shift-Left en el entorno de desarrollo local y pipelines de integración continua (CI/CD).

## **3. Metodología y Entorno de Auditoría**

La evaluación se ejecutó bajo la siguiente arquitectura de pruebas:

1. **Snyk CLI:** Ejecución de escaneos estáticos (`snyk code test`) y de cadena de suministro (`snyk test --all-projects`).

2. **Servidor MCP de Snyk en Cursor IDE:** Integración mediante el protocolo MCP ejecutando `snyk mcp` vía `cmd.exe` para permitir la auditoría y sugerencia contextual de parches por parte de agentes de IA.

3. **Alcance de Evaluación:**

   * `backend/`: Código Node.js/Express, controladores de negocio y manifiesto `package.json`.

   * `frontend/`: Aplicación React y manifiestos `package.json` / `package-lock.json`.

## **4. Matriz Obligatoria de Vulnerabilidades**

| \# | Vulnerabilidad / Hallazgo | Tipo | Identificador / CWE | Severidad Inicial | CVSS v3.1 | Ubicación en `ResiReport` | Estado Final | 
| ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | 
| **1** | **Regular Expression Denial of Service (ReDoS)** | **SAST** | `javascript/reDOS` / CWE-400 | **HIGH** | 7.5 | `backend/src/controllers/residentController.js` (Líneas 77–85) | **REMEDIADO** | 
| **2** | **Deserialization of Untrusted Data** | **SCA** | `CVE-2026-42211` / CWE-502 | **CRITICAL** | 9.1 | `frontend/package.json` (`react-router-dom@7.13.1`) | **REMEDIADO** | 
| **3** | **Prototype Pollution / Response Splitting** | **SCA** | `CVE-2026-42033` / `CVE-2026-42035` | **CRITICAL** | 9.1 | `frontend/package.json` (`axios@1.13.6`) | **REMEDIADO** | 

## **5. Fichas Técnicas de Remediación**

### **Ficha 1: Regular Expression Denial of Service (ReDoS) — SAST**

* **Causa Raíz:** Concatenación e interpolación directa de valores no sanitizados ingresados por el usuario (`torre`, `apartamento`) dentro de una instancia `new RegExp()`, permitiendo metacaracteres que causan evaluación catastrófica del motor Regex.

* **Impacto CID:** **Disponibilidad (Alta)**. Un atacante puede enviar cadenas maliciosas que bloqueen el hilo principal de ejecución (*Event Loop*) de Node.js.

* **Código ANTES (Vulnerable):**

  ```
  const aptExists = await User.findOne({
    rol: 'resident',
    torre: { $regex: new RegExp(`^${torre.trim()}$`, 'i') },
    apartamento: { $regex: new RegExp(`^${apartamento.trim()}$`, 'i') },
  });
  
  ```

* **Código DESPUÉS (Remediado):**

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

* **Verificación de Re-escaneo:** El re-escaneo SAST confirmó **0 hallazgos de ReDoS** en dicho bloque.

### **Ficha 2: Deserialización de Datos No Confiables — SCA (`react-router-dom`)**

* **Causa Raíz:** Vulnerabilidad transitiva arrastrada desde `react-router@7.13.1` (`CVE-2026-42211`) en el procesamiento de rutas deserializadas.

* **Impacto CID:** **Integridad (Alta) / Confidencialidad (Media)**. Riesgo de manipulación del estado de la aplicación en cliente.

* **Remediación Aplicada:** Actualización del paquete principal en `frontend/package.json`.

  * Versión anterior: `^7.13.1`

  * Versión instalada: `^7.14.2`

* **Evaluación de Incompatibilidad:** Riesgo bajo, manteniendo total compatibilidad con la API existente.

### **Ficha 3: Prototype Pollution y HTTP Response Splitting — SCA (`axios`)**

* **Causa Raíz:** Control deficiente de cabeceras en peticiones salientes (`CVE-2026-42035`) y contaminación de prototipos globales (`CVE-2026-42033`) en la versión de Axios instalada.

* **Impacto CID:** **Confidencialidad (Alta) / Integridad (Alta)**. Riesgo de inyección de encabezados HTTP o alteración de propiedades de objetos.

* **Remediación Aplicada:** Actualización de la librería cliente en `frontend/package.json`.

  * Versión anterior: `^1.13.6`

  * Versión instalada: `^1.15.2`

* **Evaluación de Incompatibilidad:** Riesgo medio con validación estricta de cabeceras sin romper endpoints.

## **6. Registro de Cambios de Dependencias y Re-Escaneos**

### **Tabla Comparativa de Versiones Frontend (SCA)**

| Paquete | Versión Anterior | Versión Actualizada | Hallazgos Resueltos | Evaluación de Riesgo de Salto | 
| ----- | ----- | ----- | ----- | ----- | 
| `axios` | `^1.13.6` | `^1.15.2` | Prototype Pollution (`CVE-2026-42033`, `CVE-2026-42264`), HTTP Response Splitting (`CVE-2026-42035`) | Medio: Misma API, validación de cabeceras más estricta | 
| `react-router-dom` | `^7.13.1` | `^7.14.2` | Deserialización no confiable en `react-router` (`CVE-2026-42211`) | Bajo: Sin cambios incompatibles | 

### **Resultados de Re-Escaneos de Verificación**

* **Re-escaneo SAST:** La ejecución de `snyk code test` redujo los hallazgos de severidad ALTA de 9 a 7 (extinguiendo los vectores de ReDoS en `residentController.js`).

* **Re-escaneo SCA Crítico:** Un nuevo escaneo en el frontend filtrado con `--severity-threshold=critical` devolvió **0 hallazgos abiertos** en las dependencias declaradas.

* **Observación Técnica sobre `npm audit`:** Aunque `npm audit` reporta una vulnerabilidad crítica transitiva en `proxy-addr` (1.1.0–2.0.7), esta queda fuera de los paquetes directos declarados como críticos por Snyk en el árbol principal de `package.json`.

## **7. Estrategia y Controles Preventivos Shift-Left**

### **7.1 Guardrailes en el IDE (`.cursorrules`)**

Ubicación: `.cursor/.cursorrules`

```
# Reglas de Seguridad Shift-Left para el Agente

- Neutraliza metacaracteres con funciones de escape (ej. escapeRegExp) antes de instanciar expresiones regulares dinámicas (new RegExp) para prevenir ReDoS (CWE-400).
- Valida y sanitiza las entradas del usuario en los controladores de Express utilizando esquemas strictly definidos (Zod o Joi).
- Mantén las dependencias actualizadas evitando paquetes con vulnerabilidades Críticas o Altas reportadas por Snyk.

```

### **7.2 Security Gate en CI/CD (GitHub Actions)**

Ubicación: `.github/workflows/security-gate.yml`

```
name: Snyk Security Gate

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Configurar Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Snyk SCA Security Gate Check
        run: npx snyk test --all-projects --severity-threshold=high
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}

      - name: Snyk SAST Security Gate Check
        run: npx snyk code test --severity-threshold=high
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}

```

## **8. Respuestas a las Preguntas de Cierre**

1. **¿Cuál de las tres vulnerabilidades representa mayor riesgo real y por qué?**
   El **ReDoS (CWE-400)** en `residentController.js` representa el mayor riesgo real. A diferencia de fallos en dependencias cuyos métodos pueden no ser alcanzados en tiempo de ejecución, este vector afectaba directamente a un endpoint de la API expuesto al usuario. Un atacante podía enviar valores maliciosos en `torre` o `apartamento` para colapsar el motor de expresiones regulares, consumiendo el 100% de la CPU y causando la caída del servicio de la aplicación.

2. **¿La mayor puntuación CVSS siempre debe corregirse primero?**
   No. CVSS mide la severidad intrínseca teórica de un fallo sin considerar el contexto de la aplicación. La priorización operativa debe basarse en el *Priority Score* contextual y la alcanzabilidad (*Reachability*). Una vulnerabilidad SAST alcanzable en un endpoint público debe solucionarse antes que un CVSS 9.0 en una librería transitiva que no es invocada por el código de producción.

3. **¿Qué diferencia hay entre vulnerabilidad identificada y vulnerabilidad explotable?**
   Una vulnerabilidad identificada es la presencia de un defecto en el código o de una librería desactualizada en el manifiesto. Es explotable únicamente cuando existen los parámetros de entrada expuestos, los permisos adecuados y la ruta de ejecución requerida para que un atacante pueda desencadenar la falla en un entorno operativo.

4. **¿Qué impacto tiene sobre CID (Confidencialidad, Integridad y Disponibilidad)?**

   * **Confidencialidad:** Fuga potencial de credenciales o cabeceras mediante *HTTP Response Splitting* (`axios`).

   * **Integridad:** Modificación de prototipos globales del entorno mediante *Prototype Pollution* (`axios`).

   * **Disponibilidad:** Denegación de servicio en el servidor por consumo asimétrico de recursos al procesar expresiones regulares no neutralizadas (`ReDoS`).

5. **¿Qué control habría detectado el problema antes de producción?**
   La implementación de un análisis estático de código (**SAST**) integrado directamente en el IDE durante la fase de desarrollo (mediante Snyk CLI / MCP y reglas linter), reforzado con ganchos locales (*pre-commit hooks*) que impidan guardar cambios con patrones inseguros.

6. **¿Cómo llevaría ese control al CI/CD?**
   Mediante la integración de un **Security Gate automático en GitHub Actions** (`security-gate.yml`). Al configurar `--severity-threshold=high`, la tubería de integración continua falla (retornando `exit code 1`) ante la detección de vulnerabilidades que violen las políticas, bloqueando la fusión (*merge*) a ramas principales.

7. **¿Qué limitaciones observó en la automatización y qué parte requiere criterio humano?**
   La automatización permite descubrir vectores masivamente y aplicar parches sintácticos rápidamente. Sin embargo, **el criterio humano es indispensable** para validar la lógica de negocio, evaluar si un parche como `escapeRegExp` altera la experiencia esperada en las búsquedas y verificar la ausencia de regresiones en los flujos funcionales del aplicativo.