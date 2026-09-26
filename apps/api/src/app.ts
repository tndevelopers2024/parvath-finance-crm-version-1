import express from "express";
import path from "node:path";
import { existsSync } from "node:fs";
import cors from "cors";
import helmet from "helmet";
import session from "express-session";
import MongoStore from "connect-mongo";
import pino from "pino";
import { pinoHttp } from "pino-http";
import { rateLimit } from "express-rate-limit";
import { ZodError } from "zod";
import { config } from "./config.js";
import { db, mongoClient } from "./db.js";
import { auth } from "./auth.js";
import { clients } from "./clients.js";
import { workflows } from "./workflows.js";
import { reporting } from "./reporting.js";
import { documents } from "./documents.js";
import { HttpError, requestId, requireAuth } from "./security.js";
export const logger = pino({
  level: config.NODE_ENV === "test" ? "silent" : "info",
  redact: [
    "req.headers.cookie",
    "req.headers.authorization",
    "password",
    "email",
    "phone",
    "body",
  ],
});
export const sessionStore = MongoStore.create({
  clientPromise: Promise.resolve(mongoClient),
  dbName: config.MONGODB_DB,
  collectionName: "sessions",
  stringify: false,
  autoRemove: "disabled", // TTL index is installed by db:migrate.
});
export const isAllowedOrigin = (origin?: string, host?: string): boolean => {
  if (!origin) return true;
  if (
    origin === config.APP_ORIGIN ||
    (host && (origin === `https://${host}` || origin === `http://${host}`)) ||
    origin === "https://parvath-finance-crm-production.up.railway.app" ||
    origin.endsWith(".railway.app") ||
    origin.endsWith(".vercel.app")
  ) {
    return true;
  }
  try {
    const url = new URL(origin);
    const hostname = url.hostname;
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "[::1]" ||
      hostname.endsWith(".localhost")
    ) {
      return true;
    }
    if (
      config.NODE_ENV !== "production" &&
      (/^192\.168\.\d+\.\d+$/.test(hostname) ||
        /^10\.\d+\.\d+\.\d+$/.test(hostname) ||
        /^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$/.test(hostname))
    ) {
      return true;
    }
  } catch {
    return false;
  }
  return false;
};

export const app = express();
app.disable("x-powered-by");
app.set("trust proxy", config.TRUST_PROXY);
app.set("json replacer", (_k: string, v: unknown) =>
  typeof v === "bigint" ? v.toString() : v,
);
app.use(
  requestId,
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https:"],
        imgSrc: ["'self'", "data:", "blob:", "https:"],
        fontSrc: ["'self'", "https:", "data:"],
        connectSrc: ["'self'", "https:", "wss:"],
      },
    },
  }),
  cors({
    origin: (origin, callback) => {
      if (isAllowedOrigin(origin)) {
        callback(null, true);
      } else {
        callback(null, false);
      }
    },
    credentials: true,
  }),
);
app.use(
  pinoHttp({
    logger,
    autoLogging: config.NODE_ENV !== "test",
    serializers: {
      req: (req) => ({
        id: req.id,
        method: req.method,
        path: String(req.url).split("?")[0],
      }),
      res: (res) => ({ statusCode: res.statusCode }),
    },
  }),
);
app.get("/api/health", (_req, res) => res.json({ data: { status: "ok" } }));
app.get("/api/ready", async (_req, res) => {
  await db.native.command({ ping: 1 });
  if (
    !(await db.native
      .collection<any>("schemaVersions")
      .findOne({ _id: "001-mongodb" }))
  )
    throw new HttpError(503, "Database setup is incomplete; run db:migrate");
  res.json({ data: { status: "ready", database: "mongodb" } });
});
app.use("/api", (_req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});
app.use(
  "/api",
  rateLimit({
    windowMs: 60000,
    limit: 600,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler: (_req, _res, next) =>
      next(new HttpError(429, "Too many requests. Please try again shortly.")),
  }),
  express.json({ limit: "2mb" }),
);
app.use(
  session({
    store: sessionStore,
    name: "parvath.sid",
    secret: config.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: config.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 8 * 60 * 60 * 1000,
    },
  }),
);
app.use("/api", (req, _res, next) => {
  if (!["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    const host = req.get("host");
    if (!isAllowedOrigin(req.headers.origin, host))
      throw new HttpError(403, "Origin is not allowed");
    if (!req.session.csrf || req.headers["x-csrf-token"] !== req.session.csrf)
      throw new HttpError(403, "Security token expired. Refresh the page.");
  }
  next();
});
app.use("/api/auth", auth);
app.get("/api/openapi.json", (_req, res) =>
  res.sendFile(
    existsSync(path.resolve("docs/openapi.json"))
      ? path.resolve("docs/openapi.json")
      : path.resolve("../../docs/openapi.json"),
  ),
);
app.use("/api", requireAuth);
app.use("/api/clients", clients);
app.use("/api", workflows, reporting, documents);
app.use("/api", (_req, _res) => {
  throw new HttpError(404, "Endpoint not found");
});
const webDistCandidates = [
  path.resolve("apps/web/dist"),
  path.resolve("../../apps/web/dist"),
  path.resolve("dist/apps/web"),
];
const webDistPath = webDistCandidates.find((p) =>
  existsSync(path.join(p, "index.html")),
);
if (webDistPath) {
  app.use(express.static(webDistPath));
  app.use((_req, res) => {
    res.sendFile(path.join(webDistPath, "index.html"));
  });
}
app.use(
  (
    err: any,
    req: express.Request,
    res: express.Response,
    _next: express.NextFunction,
  ) => {
    const status =
      err instanceof HttpError
        ? err.status
        : err instanceof ZodError
          ? 422
          : err.code === 11000 || err.code === 112 || err.code === 251
            ? 409
            : err.code === "RECORD_NOT_FOUND"
              ? 404
              : err.code === "INVALID_RECORD" || err.code === 121
                ? 422
                : err.code === "LIMIT_FILE_SIZE"
                  ? 413
                  : 500;
    const message =
      err instanceof ZodError
        ? "Please correct the highlighted fields"
        : status === 409 && !(err instanceof HttpError)
          ? "Record conflict. Refresh and retry."
          : status === 413
            ? "File exceeds the 10 MB limit"
            : status === 500
              ? "An unexpected error occurred"
              : err.message;
    if (status >= 500)
      logger.error(
        { requestId: req.requestId, errorType: err.name, code: err.code },
        "Request failed",
      );
    if (res.headersSent) return;
    res.status(status).json({
      error: {
        message,
        details:
          err instanceof ZodError
            ? err.flatten()
            : err instanceof HttpError
              ? err.details
              : undefined,
        requestId: req.requestId,
      },
    });
  },
);
