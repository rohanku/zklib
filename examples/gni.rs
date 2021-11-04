use zklib::{graph::{GraphPair, GNIProver, GNIVerifier, Graph}, run_interactive_proof};

fn main() {
    let instance = GraphPair {
        g0: Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]),
        g1: Graph::new(4, vec![(0, 2), (2, 3), (1, 3), (2, 1), (3, 0)]),
    };
    let mut prover = GNIProver{
        sent_guess: false,
        instance: &instance,
    };
    let mut verifier = GNIVerifier{b:false, instance: &instance};
    run_interactive_proof(&mut prover, &mut verifier);
}
