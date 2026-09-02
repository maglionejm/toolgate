import { Hono } from "hono";
import { ToolgateError } from "@toolgate/core";
import type { AppContext } from "./context.js";
import { controlRoutes, tokenRoute } from "./control.js";
import { gateRoutes } from "./gate.js";

export function createApp(ctx: AppContext): Hono {
  const app = new Hono();

  app.get("/healthz", (c) =>
    c.json({ ok: true, issuer: ctx.config.issuer, control_kid: ctx.keys.control.kid }),
  );

  app.route("/v1/control", controlRoutes(ctx));
  app.route("/v1/token", tokenRoute(ctx));
  app.route("/v1/gate", gateRoutes(ctx));

  app.onError((err, c) => {
    if (err instanceof ToolgateError) {
      // 202-class codes are flow states, not failures; they are returned inline
      // by handlers — reaching here means a real rejection.
      const status = err.httpStatus === 202 ? 409 : err.httpStatus;
      return c.json(err.toJSON(), status as 400);
    }
    console.error("[toolgate] unhandled error:", err);
    return c.json({ error: { code: "TG_INTERNAL", message: "internal error" } }, 500);
  });

  return app;
}
