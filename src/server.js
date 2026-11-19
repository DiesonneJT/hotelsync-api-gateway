require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { createProxyMiddleware } = require("http-proxy-middleware");

const { client, metricsMiddleware, servicesUp } = require("./metrics");

const app = express();
app.disable("x-powered-by");
app.use(cors({ origin: true, credentials: true }));
app.use(metricsMiddleware);

// Cabeceras basicas de seguridad HTTP y mitigacion CVE-2026-111497 (Brotli).
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  const contentEncoding = (req.headers["content-encoding"] || "").toLowerCase();
  if (contentEncoding.includes("br")) {
    return res.status(415).json({ error: "Content-Encoding br no soportado por seguridad" });
  }
  if (req.headers["accept-encoding"]) {
    req.headers["accept-encoding"] = req.headers["accept-encoding"]
      .split(",")
      .map((s) => s.trim())
      .filter((s) => !s.startsWith("br"))
      .join(", ");
  }
  next();
});

// Limitador en memoria contra fuerza bruta en rutas de autenticacion.
const intentosAuth = new Map();
function limitarAuth(req, res, next) {
  if (!req.path.startsWith("/usuarios/auth/login") && !req.path.startsWith("/usuarios/auth/register")) {
    return next();
  }
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
  const ahora = Date.now();
  const ventanaMs = 60 * 1000;
  const maxIntentos = 25;
  const registro = intentosAuth.get(ip) || { conteo: 0, inicio: ahora };

  if (ahora - registro.inicio > ventanaMs) {
    registro.conteo = 0;
    registro.inicio = ahora;
  }
  registro.conteo += 1;
  intentosAuth.set(ip, registro);

  if (registro.conteo > maxIntentos) {
    return res.status(429).json({ error: "Demasiados intentos. Por favor espera un minuto." });
  }
  next();
}
app.use(limitarAuth);

// Mismo secreto que usa servicio-usuarios.
const JWT_SECRET = process.env.JWT_SECRET || "cambiar_en_produccion";

// Rutas publicas que no requieren token.
const RUTAS_PUBLICAS = [
  "/usuarios/auth/register",
  "/usuarios/auth/login"
];

// Mapa de rutas del gateway hacia cada microservicio.
const servicios = {
  "/disponibilidad": process.env.URL_SERVICIO_DISPONIBILIDAD,
  "/reservas": process.env.URL_SERVICIO_RESERVAS,
  "/recepcion": process.env.URL_SERVICIO_RECEPCION,
  "/housekeeping": process.env.URL_SERVICIO_HOUSEKEEPING,
  "/propiedades": process.env.URL_SERVICIO_PROPIEDADES,
  "/channel": process.env.URL_SERVICIO_CHANNEL_MANAGER,
  "/facturacion": process.env.URL_SERVICIO_FACTURACION,
  "/fidelizacion": process.env.URL_SERVICIO_FIDELIZACION,
  "/analytics": process.env.URL_SERVICIO_ANALYTICS,
  "/usuarios": process.env.URL_SERVICIO_USUARIOS,
  "/archivos": process.env.URL_SERVICIO_ARCHIVOS,
  "/resenas": process.env.URL_SERVICIO_RESENAS
};

/**
 * Determina si una ruta esta en la lista blanca de rutas publicas.
 */
function esRutaPublica(path) {
  return RUTAS_PUBLICAS.some((publica) => path === publica || path.startsWith(publica + "/"));
}

/**
 * Middleware opcional de verificacion JWT.
 * - Si el header Authorization tiene un token valido, adjunta req.user.
 * - Si no hay token o es invalido, permite continuar con req.user = null.
 * Esto evita romper el flujo de demo mientras se integra el frontend.
 */
function verificarJwtOpcional(req, res, next) {
  if (esRutaPublica(req.path)) {
    req.user = null;
    return next();
  }

  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    req.user = null;
    return next();
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
  } catch (error) {
    req.user = null;
  }

  next();
}

app.use(verificarJwtOpcional);

// Limpiamos primero cualquier header x-user-* entrante para evitar
// suplantacion de identidad (header spoofing) y solo los inyectamos si
// provienen de un JWT verificado.
app.use((req, res, next) => {
  delete req.headers["x-user-id"];
  delete req.headers["x-user-rol"];
  delete req.headers["x-user-email"];

  if (req.user) {
    req.headers["x-user-id"] = String(req.user.id || "");
    req.headers["x-user-rol"] = String(req.user.rol || "");
    req.headers["x-user-email"] = String(req.user.email || "");
  }
  next();
});

app.get("/health", (req, res) => res.json({ estado: "ok", servicio: "api-gateway", rutas: Object.keys(servicios) }));

app.get("/metrics", async (req, res) => {
  res.set("Content-Type", client.register.contentType);
  res.end(await client.register.metrics());
});

// Endpoint de estado de todos los microservicios (demuestra despliegue independiente).
app.get("/status", async (req, res) => {
  const resultados = {};
  for (const [ruta, target] of Object.entries(servicios)) {
    if (!target) { resultados[ruta] = { estado: "no configurado" }; continue; }
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      const resp = await fetch(`${target.replace(/\/$/, "")}/health`, { signal: controller.signal });
      clearTimeout(timer);
      const data = await resp.json().catch(() => ({}));
      resultados[ruta] = { estado: resp.ok ? "online" : "error", detalle: data };
      servicesUp.set({ service: ruta }, resp.ok ? 1 : 0);
    } catch (err) {
      resultados[ruta] = { estado: "offline", error: err.message };
      servicesUp.set({ service: ruta }, 0);
    }
  }
  res.json({ gateway: "online", servicios: resultados });
});

// Proxy hacia cada microservicio. Se reescribe el path agregando /api internamente.
for (const [ruta, target] of Object.entries(servicios)) {
  if (!target) continue;

  app.use(
    ruta,
    createProxyMiddleware({
      target,
      changeOrigin: true,
      pathRewrite: (path) => {
        // El path aqui llega sin el prefijo de la ruta del proxy.
        // Los archivos se sirven estaticamente bajo /archivos en el servicio-archivos.
        // Solo la subida (/archivos/subir) se reescribe al endpoint /api/subir.
        if (ruta === "/archivos") {
          if (path === "/subir") return "/api/subir";
          return `/archivos${path}`;
        }
        return `/api${path}`;
      },
      on: {
        error: (err, req, res) => {
          const origin = req.headers.origin;
          if (origin) {
            res.setHeader("Access-Control-Allow-Origin", origin);
            res.setHeader("Access-Control-Allow-Credentials", "true");
          }
          res.status(502).json({ error: `Servicio ${ruta} no disponible`, detalle: err.message });
        },
        proxyReq: (proxyReq, req) => {
          // Limpiar headers suplantados y reenviar solo los del usuario autenticado.
          proxyReq.removeHeader("x-user-id");
          proxyReq.removeHeader("x-user-rol");
          proxyReq.removeHeader("x-user-email");
          if (req.user) {
            proxyReq.setHeader("x-user-id", String(req.user.id || ""));
            proxyReq.setHeader("x-user-rol", String(req.user.rol || ""));
            proxyReq.setHeader("x-user-email", String(req.user.email || ""));
          }
        },
        proxyRes: (proxyRes, req, res) => {
          // Asegurar headers CORS en la respuesta del proxy.
          const origin = req.headers.origin;
          if (origin) {
            proxyRes.headers["access-control-allow-origin"] = origin;
            proxyRes.headers["access-control-allow-credentials"] = "true";
          }
        }
      }
    })
  );
}

const PUERTO = process.env.PORT || 3010;

app.listen(PUERTO, () => {
  console.log(`[api-gateway] Escuchando en http://localhost:${PUERTO}`);
});
