// Wallet emulator (Node.js / Track A) — CLI dispatcher.
//
// Mirrors the Go binary at tools/wallet-emulator/ so operators can swap
// between the two without learning a new interface. Track A leans on the
// published @0xpolygonid/js-sdk wallet primitives; Track B reimplements
// them in Go. See README.md for the trade-offs.
//
// Subcommands:
//   identity init    Create a fresh iden3 identity. Persist its private state.
//   identity show    Print the DID + state for an existing identity file.
//   auth             Run the full Privado auth flow against a proxy.
//
// Security: identity files contain a private key. Store them in a
// secret manager (AWS Secrets Manager / Vault / …) and never commit.

import { Command } from "commander";

import { runIdentityInit, runIdentityShow } from "./identity.js";
import { runAuth } from "./auth.js";

const program = new Command();
program
  .name("wallet-emulator-js")
  .description("Headless iden3 wallet emulator (Node.js). Track A — see RD-948.")
  .version("0.1.0-phase1a");

const identity = program.command("identity");

identity
  .command("init")
  .description("Create a fresh iden3 identity. Prints DID + state for one-time on-chain registration.")
  .requiredOption("--out <file>", "Path to write the new identity JSON file.")
  .action(async (opts: { out: string }) => {
    try {
      await runIdentityInit(opts.out);
    } catch (err) {
      console.error(`identity init: ${formatError(err)}`);
      process.exit(1);
    }
  });

identity
  .command("show")
  .description("Print DID + state for an existing identity file.")
  .requiredOption("--identity <file>", "Path to the identity JSON file.")
  .action(async (opts: { identity: string }) => {
    try {
      await runIdentityShow(opts.identity);
    } catch (err) {
      console.error(`identity show: ${formatError(err)}`);
      process.exit(1);
    }
  });

program
  .command("auth")
  .description("Run the full Privado auth flow. Prints the issued JWT on success.")
  .requiredOption("--proxy <url>", "Proxy base URL (e.g. https://staging-proxy.example.com).")
  .requiredOption("--identity <file>", "Path to the identity JSON file.")
  .option(
    "--state-rpc <url>",
    "RPC endpoint for the Privado state contract. Defaults to the canonical Privado mainnet RPC.",
  )
  .action(async (opts: { proxy: string; identity: string; stateRpc?: string }) => {
    try {
      const jwt = await runAuth(opts.proxy, opts.identity, opts.stateRpc);
      console.log(jwt);
    } catch (err) {
      console.error(`auth: ${formatError(err)}`);
      process.exit(1);
    }
  });

function formatError(err: unknown): string {
  if (err instanceof Error) {
    return err.stack ?? err.message;
  }
  return String(err);
}

program.parseAsync(process.argv).catch((err) => {
  console.error(formatError(err));
  process.exit(1);
});
