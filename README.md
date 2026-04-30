# copyfail-clj

Clojure/JVM build of the copyfail proof of concept.

It uses the JDK foreign-function API to call the Linux syscalls needed by the AF_ALG/splice path, then runs `su`.

## Requirements

- Linux & Java
- Clojure CLI & JDK to build

Only `amd64` and `arm64` payloads are included.

## Build

```sh
clojure -T:build uber
```

The jar is written to:

```sh
target/copyfail-0.1.0-standalone.jar
```

Or just grab the [release](https://github.com/volysandro/copyfail-jar/releases/tag/0.1.0)!

## Run

```sh
java --enable-native-access=ALL-UNNAMED -jar target/copyfail-0.1.0-standalone.jar
```

Some current JDKs will still run without `--enable-native-access=ALL-UNNAMED`, but they may warn about restricted native access. Keep the flag in normal usage so the command keeps working as JVM defaults tighten.

For help:

```sh
java --enable-native-access=ALL-UNNAMED -jar target/copyfail-0.1.0-standalone.jar --help
```

## Clean

```sh
clojure -T:build clean
```
