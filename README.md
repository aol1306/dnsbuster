# dnsbuster

Dnsbuster is an asynchronous subdomain enumeration tool. Unlike other tools with similar purpose which work sequentially, dnsbuster allows you to set target QPS (Query per Second) value and then queries the DNS server in parallel. This should lead to increased enumeration speed.

If you don't care about overloading the DNS server you're targetting, generally you can increase QPS for as long as the queries don't timeout.

## Usage

```
dnsbuster [OPTIONS] --subdomains <SUBDOMAINS> --target <TARGET>

Options:
  -s, --subdomains <SUBDOMAINS>  Path to subdomains file
  -t, --target <TARGET>          Target domain to enumerate
  -n, --ns <NS>                  Name server to use (example: 1.1.1.1:53)
  -q, --qps <QPS>                Queries per Second [default: 10]
  -d, --debug                    Enable debug output
  -h, --help                     Print help information
  -V, --version                  Print version information
```

## Building

Dnsbuster is written in Rust, and can be built with cargo:

```
cargo build --release
```

If you don't have the Rust toolchain, you can get it from https://rustup.rs/.
