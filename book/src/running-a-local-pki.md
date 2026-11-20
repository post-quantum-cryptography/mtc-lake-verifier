# Running a local PKI

The test suite uses synthetic single-byte log entries, which is fine for
checking the proof math but says nothing about parsing a real,
wire-format MTC certificate. To get real certificate and landmark bytes to
test against, you need a CA — and for that, `mtc-demo` is the closest
match to the draft revision this crate targets.

## It's a CLI, not a server

`robstradling/mtc-demo` has no `serve`/HTTP mode. Every "PKI role" — CA,
cosigner, mirror, relying party, landmark manager — is a CLI subcommand
that reads and writes a local `./mtc-state.json` file. "Running the PKI"
means running this sequence of commands, not standing up a long-lived
service.

> As covered in [Verification methodology](./verification-methodology.md),
> `mtc-demo` ships with no `LICENSE` file. Running its CLI as an external
> tool — building the binary and invoking it — is fine; copying its source
> into this crate is not, and this crate doesn't do that.

## Build it

Requires Go 1.25+ and network access (fetches `golang.org/x/crypto` and
`filippo.io/mldsa`):

```sh
git clone https://github.com/robstradling/mtc-demo
cd mtc-demo
go build -o mtc-demo ./cmd/mtc-demo/
```

## Stand up a CA, issue a certificate, allocate a landmark

Run these in an empty working directory — state persists in
`./mtc-state.json` between commands:

```sh
./mtc-demo ca init 32473.1 1               # CA ID, log number
./mtc-demo cosigner keygen 32473.1 p256    # CA's own cosigner key (ID = CA ID, §5.4)
./mtc-demo cosigner keygen 32473.100 ed25519
./mtc-demo cosigner keygen 32473.200 p256
./mtc-demo ca cert                          # -> ca-cert.pem

./mtc-demo ca add example.com               # queues a TBS cert entry (index 1)
./mtc-demo ca add test.example.com          # (index 2)
./mtc-demo ca checkpoint                    # builds the tree, prints subtree hashes

./mtc-demo cosigner sign 32473.100 0 2      # cosign each subtree the checkpoint printed
./mtc-demo cosigner sign 32473.200 0 2
./mtc-demo cosigner sign 32473.100 2 3
./mtc-demo cosigner sign 32473.200 2 3

./mtc-demo ca issue 1                       # -> cert-1.pem, for entry index 1
./mtc-demo verify cert cert-1.pem           # sanity check: PASSED

./mtc-demo landmark init 5                  # max active landmarks
./mtc-demo landmark allocate                # landmark #1, tree size 3
./mtc-demo landmark find 1                  # which landmark/subtree covers entry 1
```

A real run of this produced:

```text
$ ./mtc-demo ca checkpoint
Tree size:  3
Checkpoint: a72b77cbe9ae74ba0b715244355f4d45593d1133064c6d980fac6ead60f0ff13
Subtrees:
  [0, 2): f330518d685438ed04a7caa6f6fa06a09683570dbc6c20551280572251bffdf4
  [2, 3): ef40ac6705a414130fe50d39318e636b9be15ff562368655fc81db4e444db3fe

$ ./mtc-demo ca issue 1
Certificate issued:
  Index:    1
  Serial:   0x1000000000001
  Subtree:  [0, 2)
  Size:     498 bytes
  File:     cert-1.pem

$ ./mtc-demo verify cert cert-1.pem
Verification: PASSED

$ ./mtc-demo landmark allocate
Landmark allocated:
  Landmark #:    1
  Tree size:     3
  Trust anchor:  32473.1.1.1.1
  Subtrees:
    [0, 2): f330518d685438ed04a7caa6f6fa06a09683570dbc6c20551280572251bffdf4
    [2, 3): ef40ac6705a414130fe50d39318e636b9be15ff562368655fc81db4e444db3fe
```

## What this is missing, to be useful as a test input

`cert-1.pem` is an X.509-encoded certificate carrying an `MTCProof`
extension (§6.2 of the spec). Nothing in this crate yet parses that
extension out into the `(index, start, end, proof, subtree_hash)` tuple
`verify_subtree_inclusion_proof` expects — see
[Roadmap](./roadmap.md). Until that parser exists, this walkthrough is
useful for manual sanity-checking and as a target to build the parser
against, but it isn't wired into the automated test suite.
