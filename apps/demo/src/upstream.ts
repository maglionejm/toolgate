import { Hono } from "hono";

/**
 * Mock third-party APIs (a CRM and an email service). They require real
 * credentials — exactly the secrets the agent must never see. If Toolgate
 * fails to inject them, these return 401 and the demo fails loudly.
 */
export function makeUpstreams(secrets: { crm: string; email: string }): Hono {
  const app = new Hono();

  app.post("/crm/tools/:tool", async (c) => {
    if (c.req.header("authorization") !== `Bearer ${secrets.crm}`) {
      return c.json({ error: "unauthorized: bad or missing CRM credential" }, 401);
    }
    const tool = c.req.param("tool");
    const args: Record<string, unknown> = await c.req
      .json<Record<string, unknown>>()
      .catch(() => ({}));
    switch (tool) {
      case "read_contact":
        return c.json({
          contact: { id: args.contactId ?? "c-001", name: "Rivera, Ana", company: "Globex" },
        });
      case "list_contacts":
        return c.json({ contacts: 42 });
      case "delete_contact":
        return c.json({ deleted: args.contactId });
      default:
        return c.json({ error: `unknown tool ${tool}` }, 404);
    }
  });

  app.post("/email/tools/send_email", async (c) => {
    if (c.req.header("x-api-key") !== secrets.email) {
      return c.json({ error: "unauthorized: bad or missing email credential" }, 401);
    }
    const args = await c.req.json<Record<string, unknown>>();
    return c.json({ sent: true, to: args.to, messageId: `msg_${Date.now()}` });
  });

  return app;
}
