# dRNG

This repo contains benchmarks for the main operation of the generation phase and verification of random numbers produced by the [drand](https://github.com/dedis/drand) protocol.

# Requirements

First make sure you have Go version [1.13](https://golang.org/dl/) or newer installed.

The benchmark requires only Go and a few third-party Go-language dependencies that can be installed automatically as follows:

```
go get go.dedis.ch/kyber
```

# Running the benchmark
You can run the benchmark by running:

```
go test -bench=.
```