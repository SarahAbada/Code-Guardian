import express, {
  type Express,
  type NextFunction,
  type Request,
  type Response,
} from "express";
import cors, { type CorsOptions } from "cors";
import pinoHttp from "pino-http";
import router from "./routes";
import { logger } from "./lib/logger";

const app: Express = express();

const JSON_BODY_LIMIT = "25kb";

function parseAllowedOrigins(): string[] | null {
  const value = process.env["ALLOWED_ORIGINS"];
  if (!value) return null;
  return value
    .split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);
}

const explicitAllowed = parseAllowedOrigins();

const replitDomainSuffixes = [".replit.dev", ".repl.co", ".replit.app"];

function isReplitDomain(origin: string): boolean {
  try {
    const url = new URL(origin);
    return replitDomainSuffixes.some((suffix) =>
      url.hostname.endsWith(suffix),
    );
  } catch {
    return false;
  }
}

const corsOptions: CorsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);

    if (explicitAllowed) {
      if (explicitAllowed.includes(origin)) return callback(null, true);
      return callback(new Error(`Origin ${origin} not in allowlist`));
    }

    if (
      origin.startsWith("http://localhost") ||
      origin.startsWith("http://127.0.0.1")
    ) {
      return callback(null, true);
    }

    if (isReplitDomain(origin)) return callback(null, true);

    return callback(new Error(`Origin ${origin} not in allowlist`));
  },
  credentials: false,
};

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return {
          id: req.id,
          method: req.method,
          url: req.url?.split("?")[0],
        };
      },
      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);
app.use(cors(corsOptions));
app.use(express.json({ limit: JSON_BODY_LIMIT }));
app.use(express.urlencoded({ extended: true, limit: JSON_BODY_LIMIT }));

app.use("/api", router);

app.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
  if (res.headersSent) {
    next(err);
    return;
  }

  if (err instanceof Error) {
    if (err.message.startsWith("Origin ") && err.message.includes("not in allowlist")) {
      req.log?.warn({ origin: req.headers.origin }, "CORS request rejected");
      res.status(403).json({ message: "Origin not allowed by CORS policy." });
      return;
    }

    const errWithCode = err as Error & { type?: string; status?: number };
    if (errWithCode.type === "entity.too.large" || errWithCode.status === 413) {
      res.status(413).json({
        message: `Request body exceeds the ${JSON_BODY_LIMIT} JSON limit.`,
      });
      return;
    }

    if (
      errWithCode.type === "entity.parse.failed" ||
      errWithCode.status === 400
    ) {
      res.status(400).json({ message: "Invalid JSON request body." });
      return;
    }
  }

  req.log?.error({ err }, "Unhandled application error");
  res.status(500).json({ message: "Internal server error." });
});

export default app;
