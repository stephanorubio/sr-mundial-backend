# Cafeína Web Project

## 🚀 Deployment
El despliegue es automático vía Render al hacer push a `main`.

## ⚠️ Troubleshooting (Runbook)
**Si el sitio da Error 500:**
1. Revisar logs en Render Dashboard.
2. Verificar conexión con Neon DB (`DATABASE_URL`).
3. Si el error persiste, ejecutar Rollback en Render.

**Si el API de Precios falla:**
1. El sitio usará precios en caché automáticamente.
2. Contactar al proveedor del ERP.
