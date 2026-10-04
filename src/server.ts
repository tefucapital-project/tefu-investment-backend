import { createApp } from "./app.ts";
import { env } from "./config.ts";

const app = createApp();
app.listen(env.port, () => {
  console.log(`Tefu Investment API listening on http://127.0.0.1:${env.port}`);
});
