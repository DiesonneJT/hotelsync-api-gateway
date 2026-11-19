const client = require("prom-client");

// Recopilar métricas por defecto (CPU, memoria, event loop, etc.)
client.collectDefaultMetrics({ prefix: "hotelsync_gateway_" });

// Contador de peticiones HTTP
const httpRequestsTotal = new client.Counter({
  name: "hotelsync_gateway_http_requests_total",
  help: "Total de peticiones HTTP recibidas",
  labelNames: ["method", "route", "status_code"]
});

// Histograma de duración de peticiones
const httpRequestDuration = new client.Histogram({
  name: "hotelsync_gateway_http_request_duration_seconds",
  help: "Duración de peticiones HTTP en segundos",
  labelNames: ["method", "route", "status_code"],
  buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
});

// Gauge de servicios online
const servicesUp = new client.Gauge({
  name: "hotelsync_gateway_services_up",
  help: "Número de microservicios online",
  labelNames: ["service"]
});

function metricsMiddleware(req, res, next) {
  const start = process.hrtime.bigint();
  res.on("finish", () => {
    const duration = Number(process.hrtime.bigint() - start) / 1e9;
    const route = req.route ? req.route.path : req.path;
    httpRequestsTotal.inc({ method: req.method, route, status_code: res.statusCode });
    httpRequestDuration.observe({ method: req.method, route, status_code: res.statusCode }, duration);
  });
  next();
}

module.exports = { client, metricsMiddleware, servicesUp };
