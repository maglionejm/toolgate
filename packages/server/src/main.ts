import { serve } from "@hono/node-server";
import { createAppContext } from "./context.js";
import { createApp } from "./app.js";

const port = Number(process.env.PORT ?? 8484);
const ctx = await createAppContext({ publicUrl: process.env.TOOLGATE_PUBLIC_URL ?? `http://localhost:${port}` });
const app = createApp(ctx);

serve({ fetch: app.fetch, port }, (info) => {
  console.log(`[toolgate] control plane + gate listening on :${info.port}`);
  console.log(`[toolgate] issuer: ${ctx.config.issuer}`);
  console.log(`[toolgate] admin key: ${ctx.config.adminKey}`);
});
