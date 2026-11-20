# Running a local PKI

Use this to get real certificate and landmark bytes to test against,
instead of the synthetic single-byte entries `tests/spec_vectors.rs` uses.

[`mtc-demo`](https://github.com/robstradling/mtc-demo) is a CLI that reads
and writes a local `./mtc-state.json` file — there's no server/HTTP mode.
Running its binary is fine; this repo does not vendor its source (it ships
with no LICENSE file).

## Build

Requires Go 1.25+ and network access:

```sh
git clone https://github.com/robstradling/mtc-demo
cd mtc-demo
go build -o mtc-demo ./cmd/mtc-demo/
```

## Issue a certificate and allocate a landmark

Run in an empty working directory:

```sh
./mtc-demo ca init 32473.1 1               # CA ID, log number
./mtc-demo cosigner keygen 32473.1 p256    # CA's own cosigner key (ID = CA ID)
./mtc-demo cosigner keygen 32473.100 ed25519
./mtc-demo cosigner keygen 32473.200 p256
./mtc-demo ca cert                          # -> ca-cert.pem

./mtc-demo ca add example.com               # queues a TBS cert entry (index 1)
./mtc-demo ca add test.example.com          # (index 2)
./mtc-demo ca checkpoint                    # builds the tree, prints subtree hashes

./mtc-demo cosigner sign 32473.100 0 2      # cosign each subtree checkpoint printed
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

## Using the output

`cert-1.pem` is X.509 carrying an `MTCProof` extension. Nothing in `src/`
parses that extension yet into the `(index, start, end, proof,
subtree_hash)` tuple `verify_subtree_inclusion_proof` takes — that parser
is the next piece needed to turn this into an automated test rather than a
manual walkthrough.
