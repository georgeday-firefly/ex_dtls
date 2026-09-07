# Native regression checks

Run `bash test/native/run.sh` with a C11 compiler, pthreads, OpenSSL development
headers, and pkg-config installed. On Homebrew, set
`PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"`.

The runner starts a separate process for every scenario so the once initializer
is always fresh. The first-use test holds initialization at a callback setter
until all 16 competing callers have started, then checks that they share one
method table and have distinct, usable connection contexts. It fails against the
original per-connection method construction without relying on a random crash.

The test translation unit wraps allocation and callback setup calls while
including the production C sources. Failure injection stays entirely outside the
shipped library. It covers method allocation, each callback setter, context
allocation, SSL/BIO construction, and SRTP setup. Object counters check cleanup
and a subsequent successful connection checks recovery from per-connection
failures. A method-table setup failure remains failed for that library instance;
`CRYPTO_THREAD_run_once` deliberately does not retry its initializer.

Queue checks cover 99, 100, and 101 attempted fragments, payload integrity,
capacity rejection, draining, reuse, empty reads, and invalid context errors.

CI runs this suite with AddressSanitizer/UndefinedBehaviorSanitizer and separately
with ThreadSanitizer. Locally, for example:

```sh
CFLAGS='-fsanitize=address,undefined -fno-sanitize-recover=all' bash test/native/run.sh
```

The ExUnit concurrency suite additionally completes client/server handshakes,
checks peer certificates, exchanges data both ways, and closes connections. Its
larger 50,000-context stress test is tagged `stress`; use `mix test --exclude
stress` for the shorter suite or `mix test` to include it.
