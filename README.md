# Hispana Polla Manager - Backend Core ⚽️

Este repositorio contiene el plugin personalizado para la gestión de pronósticos, cálculo de puntajes y conexión con APIs deportivas para la campaña "Polla Mundialista".

**Cliente:** Hispana de Seguros
**Tech Stack:** WordPress, PHP 8.1, MySQL, Redis.

---

## 🚀 Despliegue (Deployment)

El despliegue es automático al hacer push a la rama `main`.
Si el despliegue falla, revisar los logs en el panel de hosting y ejecutar rollback manual a la versión `v2.4-stable`.

---

## ⚠️ RUNBOOK DE INCIDENTES (Soporte Nivel 2)

Instrucciones para resolver problemas críticos durante los partidos en vivo.

### 1. Fallo de API de Resultados (SportsAPI)
**Síntoma:** Los marcadores no se actualizan automáticamente al finalizar el partido.
**Solución:**
1. Ir a `Ajustes > Polla Manager > API Status`.
2. Activar el switch **"Modo Manual / Override"**.
3. Ingresar el marcador final manualmente y guardar.
4. El sistema disparará el recálculo de puntos en segundo plano.

### 2. Error en Cálculo de Puntos
**Síntoma:** Usuarios reportan puntaje 0 a pesar de acertar.
**Solución (Vía CLI):**
Ingresar al servidor por SSH y ejecutar el comando de reparación:

```bash
# Recalcular un partido específico (ID 402)
wp hispana-polla recalculate --match_id=402 --force

# Limpiar caché de ranking
wp cache flush
