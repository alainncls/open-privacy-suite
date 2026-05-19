// Wallet emulator — headless iden3 wallet for staging / prod-build auth tests.
//
// This binary lets operators run the full Privado auth flow against a
// prod-built proxy without a real wallet on a real phone. The proxy's
// MOCK_SIGNATURES / ALLOW_MOCK_LOGIN paths are compiled out in prod
// (`-tags mockauth` is dev only); the emulator generates real iden3 ZK
// proofs that the prod verifier accepts.
//
// Subcommands:
//
//	wallet-emulator identity init  --out <file>       Create a fresh identity + auth claim.
//	                                                  Print DID + state for one-time on-chain registration.
//	wallet-emulator identity show  --identity <file>  Print DID + current state.
//	wallet-emulator auth           --proxy <url>      Full /auth/request → /auth/verify flow.
//	                               --identity <file>  Prints the issued JWT to stdout on success.
//	                               --artifacts <dir>  Path to auth-v2 circuit .wasm + .zkey.
//
// Security: the identity JSON file contains a private key. Store it in a
// secret manager (AWS Secrets Manager, Vault, etc.) and never commit it.
// See README.md for the full lifecycle.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "identity":
		if len(os.Args) < 3 {
			usageIdentity()
			os.Exit(2)
		}
		switch os.Args[2] {
		case "init":
			runIdentityInit(os.Args[3:])
		case "show":
			runIdentityShow(os.Args[3:])
		default:
			usageIdentity()
			os.Exit(2)
		}
	case "auth":
		runAuth(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `wallet-emulator — headless iden3 wallet for staging / prod-build auth tests.

USAGE
    wallet-emulator <subcommand> [flags]

SUBCOMMANDS
    identity init    Create a fresh iden3 identity. Prints DID + state for one-time on-chain registration.
    identity show    Print DID + current state for an existing identity file.
    auth             Run the full Privado auth flow against a proxy. Prints the issued JWT on success.

FLAGS
    Pass --help to any subcommand for its flags.

SECURITY
    The identity JSON file contains a private key. Keep it in a secret manager — not git.
    See tools/wallet-emulator/README.md for the credential lifecycle.`)
}

func usageIdentity() {
	fmt.Fprintln(os.Stderr, `wallet-emulator identity — manage iden3 identities.

USAGE
    wallet-emulator identity init [--out FILE]
    wallet-emulator identity show --identity FILE`)
}

func runIdentityInit(args []string) {
	fs := flag.NewFlagSet("identity init", flag.ExitOnError)
	out := fs.String("out", "", "Path to write the new identity JSON file (required).")
	_ = fs.Parse(args)
	if *out == "" {
		fmt.Fprintln(os.Stderr, "--out is required")
		os.Exit(2)
	}
	if err := identityInit(*out); err != nil {
		fmt.Fprintf(os.Stderr, "identity init: %v\n", err)
		os.Exit(1)
	}
}

func runIdentityShow(args []string) {
	fs := flag.NewFlagSet("identity show", flag.ExitOnError)
	in := fs.String("identity", "", "Path to the identity JSON file (required).")
	_ = fs.Parse(args)
	if *in == "" {
		fmt.Fprintln(os.Stderr, "--identity is required")
		os.Exit(2)
	}
	if err := identityShow(*in); err != nil {
		fmt.Fprintf(os.Stderr, "identity show: %v\n", err)
		os.Exit(1)
	}
}

func runAuth(args []string) {
	fs := flag.NewFlagSet("auth", flag.ExitOnError)
	proxy := fs.String("proxy", "", "Proxy base URL, e.g. https://staging-proxy.example.com (required).")
	ident := fs.String("identity", "", "Path to the identity JSON file (required).")
	artifactsDir := fs.String("artifacts", "tools/wallet-emulator/artifacts", "Directory containing the auth-v2 circuit .wasm and .zkey.")
	_ = fs.Parse(args)
	if *proxy == "" || *ident == "" {
		fmt.Fprintln(os.Stderr, "--proxy and --identity are required")
		os.Exit(2)
	}
	jwt, err := authFlow(*proxy, *ident, *artifactsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "auth: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(jwt)
}
