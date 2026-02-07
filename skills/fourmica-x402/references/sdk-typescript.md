# TypeScript SDK (@4mica/sdk)

## Install
```bash
npm install @4mica/sdk
```

## Configuration
- `walletPrivateKey` is required unless you provide a custom signer.
- `rpcUrl` defaults to `https://api.4mica.xyz/`.
- Optional: `ethereumHttpRpcUrl`, `contractAddress`, `adminApiKey`, `bearerToken`.
- Optional SIWE auth: call `enableAuth()` or set `authUrl` and `authRefreshMarginSecs`.

Environment variables (use `env` to set inline in shells):
- `4MICA_WALLET_PRIVATE_KEY`, `4MICA_RPC_URL`, `4MICA_ETHEREUM_HTTP_RPC_URL`,
  `4MICA_CONTRACT_ADDRESS`, `4MICA_ADMIN_API_KEY`, `4MICA_BEARER_TOKEN`,
  `4MICA_AUTH_URL`, `4MICA_AUTH_REFRESH_MARGIN_SECS`.

## Basic Client
```ts
import { Client, ConfigBuilder } from "@4mica/sdk";

const cfg = new ConfigBuilder()
  .walletPrivateKey("0x...")
  .rpcUrl("https://api.4mica.xyz/")
  .build();

const client = await Client.new(cfg);
// use client.user, client.recipient, client.rpc
await client.aclose();
```

## X402 Flow (Client/Payer)
Version 1 (JSON body):
```ts
import { Client, ConfigBuilder, X402Flow } from "@4mica/sdk";

const client = await Client.new(new ConfigBuilder().walletPrivateKey("0x...").build());
const flow = X402Flow.fromClient(client);

const res = await fetch("https://resource-url/resource");
const body = await res.json();
const requirements = body.accepts[0];

const payment = await flow.signPayment(requirements, "0xUser");
await fetch("https://resource-url/resource", {
  headers: { "X-PAYMENT": payment.header },
});
```

Version 2 (payment-required header):
```ts
import { Client, ConfigBuilder, X402Flow } from "@4mica/sdk";

const client = await Client.new(new ConfigBuilder().walletPrivateKey("0x...").build());
const flow = X402Flow.fromClient(client);

const res = await fetch("https://resource-url/resource");
const header = res.headers.get("payment-required");
if (!header) throw new Error("Missing payment-required header");

const decoded = Buffer.from(header, "base64").toString("utf8");
const paymentRequired = JSON.parse(decoded);
const accepted = paymentRequired.accepts[0];

const signed = await flow.signPaymentV2(paymentRequired, accepted, "0xUser");
await fetch("https://resource-url/resource", {
  headers: { "PAYMENT-SIGNATURE": signed.header },
});
```

## Resource Server Settlement Helper
```ts
import { Client, ConfigBuilder, X402Flow } from "@4mica/sdk";

const core = await Client.new(
  new ConfigBuilder().walletPrivateKey(process.env.RESOURCE_SIGNER_KEY!).build()
);
const flow = X402Flow.fromClient(core);

const settled = await flow.settlePayment(payment, paymentRequirements, facilitatorUrl);
console.log(settled.settlement);
await core.aclose();
```

Notes:
- `signPayment` and `signPaymentV2` require a `scheme` that includes `4mica`.
- `settlePayment` only hits `/settle`; call `/verify` before doing work.

## Key Client Methods
- `client.user`: approve and deposit collateral, sign payments, pay tabs, withdraw.
- `client.recipient`: create tabs, issue guarantees, verify guarantees, remunerate.
- `client.rpc`: admin RPCs when `adminApiKey` is configured.
