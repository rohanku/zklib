use zklib::{graph::{GraphPair, GNIProver, GNIVerifier, Graph}, run_interactive_proof};
use zklib::graph::{GNIProverMalicious, GIVerifier, GIProverMalicious};

fn main() {
    let gni_instance = GraphPair {
        g0: Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]),
        g1: Graph::new(4, vec![(0, 2), (2, 3), (1, 3), (2, 1), (3, 0)]),
    };
    let gi_instance = GraphPair {
        g0: Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]),
        g1: Graph::new(4, vec![(2, 1), (1, 0), (1, 3), (2, 3), (3, 2)]),
    };
    println!("GNI interactive proof with honest prover");
    println!("===========================================");
    let mut gni_prover = GNIProver{
        sent_guess: false,
        instance: &gni_instance,
    };
    let mut gni_verifier = GNIVerifier{b:false, instance: &gni_instance};
    run_interactive_proof(&mut gni_prover, &mut gni_verifier);

    println!("\nGNI interactive proof with malicious prover");
    println!("===========================================");
    let mut gni_malicious_prover = GNIProverMalicious{
        sent_guess: false,
        p: 0.5,
    };
    let mut gni_malicious_verifier = GNIVerifier{b:false, instance: &gi_instance};
    run_interactive_proof(&mut gni_malicious_prover, &mut gni_malicious_verifier);

    println!("\nGI interactive proof with honest prover");
    println!("===========================================");
    let mut gi_prover = GIProverMalicious{
        r: 0,
        isomorphism: Vec::new(),
        instance: &gi_instance,
        p: 0.5,
    };
    let mut gi_verifier = GIVerifier{
        r: 0,
        b: false,
        random_perm: Graph::new(0, Vec::new()),
        instance: &gi_instance,
    };
    run_interactive_proof(&mut gi_prover, &mut gi_verifier);

    println!("\nGI interactive proof with malicious prover");
    println!("===========================================");
    let mut gi_malicious_prover = GIProverMalicious{
        r: 0,
        isomorphism: Vec::new(),
        instance: &gni_instance,
        p: 0.5,
    };
    let mut gi_malicious_verifier = GIVerifier{
        r: 0,
        b: false,
        random_perm: Graph::new(0, Vec::new()),
        instance: &gni_instance,
    };
    run_interactive_proof(&mut gi_malicious_prover, &mut gi_malicious_verifier);
}
