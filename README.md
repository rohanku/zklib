# zklib

Rust implementations of zero knowledge proofs, commitment schemes, and other cryptographic protocols.

## Setup

Running `zklib` requires installing the latest version of Rust, which can be done by following the instructions [here](https://www.rust-lang.org/tools/install).

Use `cargo` to build the library:
```bash
git clone git@github.com:rohanku/zklib.git
cd zklib
cargo build
```

The project is structured as follows:
```bash
.
├── Cargo.lock
├── Cargo.toml
├── README.md
├── examples
│   └── graph_proofs.rs
└── src
    ├── graph.rs
    ├── lib.rs
    └── main.rs
```
Implementations can be found in `src`. General implementations are found in `lib.rs` and `main.rs`, while more specific protocols are found within relevant modules. Examples of running interactive proofs can be found in `examples` as well as in unit tests.

The following commands can be used to test out `zklib` implementations:
```bash
cargo test # run tests
cargo test -- --nocapture # run tests with stdout
cargo test <test> -- -nocapture # run specific test with stdout

cargo run --example <example> # run specific example
```

## Current Implementations

Brief writeups and explanations for implemented protocols.

### Zero Knowledge Proofs

#### Graph nonisomorphism (GNI) [[graph.rs](src/graph.rs#L183)]

##### Private coin

The graph nonisomorphism problem asks whether two graphs G0 and G1 are not isomorphic to one another (i.e. there exists no permutation of vertex labels that transforms one to the other). In the private coin proof system for GNI, the verifier selects a random bit b and sends a random permutation of graph Gb to the prover. The prover must then guess bit b and the verifier accepts the proof if the prover guesses correctly.

This proof has perfectly completeness since an honest, computationally unbounded prover can always determine the bit b by finding whether the random permutation lies in the equivalence class of G0 or G1 (which are disjoint if and only if G0 and G1 are nonisomorphic). It has soundness 1/2 since if G0 and G1 are isomorphic, the random permutation could have been derived from either G0 or G1 and a malicious prover can do no better than blindly guessing bit b.

#### Graph isomorphism (GI)  [[graph.rs](src/graph.rs#L7)]

##### Public coin

The graph isomorphism problem asks whether two graphs G0 and G1 are isomorphic to one another. In the public coin proof system for GI, the prover sends a random permutation of graph G0 to the verifier, who then sends back a random bit b. The prover then must provide an isomorphism from their random permutation to graph Gb, and the verifier accepts the proof if the isomorphism is correct.

This proof has perfectly completeness since if G0 and G1 are isomorphic, the random permutation must be in the same equivalence class as the two graphs and thus have an isomorphism to both of them (so, regardless of which graph the verifier chooses, the prover can find a valid isomorphism). If they are not isomorphic, the permutation must lie in the equivalence class of at most one of the two graphs and the prover will fail to prove isomorphism if the verifier chooses a graph that is not isomorphic to the permutation. Thus, the soundness for this proof is 1/2.


## Resources


#### [CS 294: Foundations of Probabilistic Proofs](https://people.eecs.berkeley.edu/~alexch/classes/CS294-F2020.html)