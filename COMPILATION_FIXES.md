# Compilation Fixes Needed

## Issues Found

1. **`loaders.DefaultSchemaLoader` is undefined**
   - Need to check the actual exported name in go-iden3-auth v2.7.8
   - May be `loaders.NewDefaultSchemaLoader()` or different struct name

2. **`auth.NewVerifier` signature**
   - May return `(*Verifier, error)` instead of just `*Verifier`
   - Already fixed to handle error return

3. **`FullVerify` parameters**
   - May not accept `nil` as third parameter
   - Already fixed to use 2 parameters only

4. **`postgres.RunContainer` vs `postgres.Run`**
   - Need to verify correct function name for testcontainers v0.31.0
   - Already using `postgres.RunContainer` with `testcontainers.WithWaitStrategy`

5. **Unused import `time`**
   - Already fixed

## Next Steps

Run `go mod tidy` and then try compiling to see remaining errors, then we can fix the exact API calls based on the actual library signatures.
