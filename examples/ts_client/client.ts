import { config as loadEnv } from "dotenv";
import path from "node:path";
import { Client, ConfigBuilder, PaymentRequirements, X402Flow } from "sdk-4mica";

// Load env files from the example directory, examples/.env, and the repo root if present.
[
  path.resolve(__dirname, ".env"),
  path.resolve(__dirname, "..", ".env"),
  path.resolve(__dirname, "..", "..", ".env"),
].forEach((envPath) => loadEnv({ path: envPath, override: false }));

const payerKey = process.env.PAYER_KEY;
const userAddress = process.env.USER_ADDRESS;
const resourceUrl = process.env.RESOURCE_URL;

if (!payerKey || !userAddress || !resourceUrl) {
  throw new Error("PAYER_KEY, USER_ADDRESS, and RESOURCE_URL must be set");
}

const pk: string = payerKey;
const ua: string = userAddress;
const resource: string = resourceUrl;

function asRecord(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  throw new Error("payment requirements must be an object");
}

async function main(): Promise<void> {
  console.log("--- x402 / 4mica flow (TypeScript SDK) ---");

  const cfg = new ConfigBuilder().walletPrivateKey(pk).build();
  const client = await Client.new(cfg);
  const flow = X402Flow.fromClient(client);

  try {
    const resp = await fetch(resource);
    if (resp.status !== 402) {
      throw new Error(`expected HTTP 402 from the resource, got ${resp.status}`);
    }
    const body = (await resp.json()) as { accepts?: unknown[] };
    const accepts = Array.isArray(body.accepts) ? body.accepts : [];
    if (!accepts.length) {
      throw new Error("resource did not return any payment requirements in 'accepts'");
    }
    const requirements = PaymentRequirements.fromRaw(asRecord(accepts[0]));

    const payment = await flow.signPayment(requirements, ua);
    const decoded = JSON.parse(Buffer.from(payment.header, "base64").toString("utf8"));

    console.log(`\nX-PAYMENT header:\n${payment.header}\n`);
    console.log("Decoded header:");
    console.log(JSON.stringify(decoded, null, 2));

    const resourceResp = await fetch(resource, {
      headers: { "X-PAYMENT": payment.header },
    });

    console.log("\nResponse from resource server:\n");
    const text = await resourceResp.text();
    try {
      console.log(JSON.stringify(JSON.parse(text), null, 2));
    } catch {
      console.log(text);
    }
  } finally {
    await client.aclose();
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
