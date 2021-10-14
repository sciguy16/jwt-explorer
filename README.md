# JWT Explorer

![Overview of JWT Explorer](images/overview.png)

## Usage

```bash
cargo run --release
```

## Features

* Decode JWTs and inspect the headers and claims
* Automatically try some common secrets
* Generate `alg:none` attack payloads
* Easily update `iat` and `exp` with various offsets
* Sign and encode tokens with common algorithms
* Accept and encode invalid JSON payloads

## License

JWT Explorer is available under the terms of both the MIT license and
the Apache License (Version 2.0).

Fonts used are distributed under the terms of the Open Font License.

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT), and
fonts/\*/LICENSE for details.
