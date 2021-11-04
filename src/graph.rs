use std::{collections::HashSet, cmp, fmt};
use rand::{thread_rng, Rng, seq::SliceRandom};
use itertools::Itertools;
use rayon::prelude::*;
use crate::{Prover, Verifier, run_interactive_proof};

// Zero-knowledge graph isomorphism proof implementation

pub enum GIProverMessage {
    // Random permutation of g0 or g1
    Graph(Graph),
    // Isomorphism between graph permutation and gb
    Isomorphism(Vec<u32>),
    // Interaction complete
    Done
}

pub struct GIVerifierMessage {
    // Random graph for prover to prove isomorphism with random permutation
    b: bool,
}

pub struct GIProver<'a> {
    // Keep track of round number
    pub r: u32,
    pub random_perm: Graph,
    pub instance: &'a GraphPair,
}

impl Prover for GIProver<'_> {
    type ProverMessage = GIProverMessage;
    type VerifierMessage = GIVerifierMessage;

    fn handle(&mut self, msg: &GIVerifierMessage) -> (GIProverMessage, bool) {
        self.r += 1;
        match self.r {
            0 => { self.random_perm = self.instance.g0.random_permutation(); (GIProverMessage::Graph(self.random_perm.clone()), false) },
            1 => (GIProverMessage::Isomorphism(self.random_perm.find_isomorphism_to(if msg.b {&self.instance.g1} else {&self.instance.g0}).unwrap()), false),
            _ => (GIProverMessage::Done, true),
        }
    }
}

pub struct GIVerifier<'a> {
    // Randomly chosen bit
    pub b: bool,
    pub instance: &'a GraphPair,
}

/*impl Verifier for GIVerifier<'_> {
    type ProverMessage = GIProverMessage;
    type VerifierMessage = GIVerifierMessage;

    fn init(&mut self) -> GIVerifierMessage {
        println!("Initializing GI instance with graphs {:?} and {:?}.", &self.instance.g0, &self.instance.g1);
        self.b = rand::thread_rng().gen_bool(0.5);
        println!("Verifier chose graph {}.", if self.b {1} else {0});
        GIVerifierMessage{gb: if self.b {self.instance.g1.random_permutation()} else {self.instance.g0.random_permutation()}}
    }

    fn handle(&mut self, msg: &GIProverMessage) -> (GIVerifierMessage, bool) {
        println!("Verifier received bit {}.", if msg.b {1} else {0});
        (GIVerifierMessage{gb: Graph::new(0, vec![])}, msg.b == self.b)
    }
}*/

#[test]
fn test_gi_interactive_proof() {
    let instance = GraphPair {
        g0: Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]),
        g1: Graph::new(4, vec![(0, 2), (2, 3), (1, 3), (2, 1), (3, 0)]),
    };
    let mut prover = GNIProver{
        sent_guess: false,
        instance: &instance,
    };
    let mut verifier = GNIVerifier{b:false, instance: &instance};
    assert!(run_interactive_proof(&mut prover, &mut verifier));
}

#[test]
fn test_gi_malicious_interactive_proof() {
    // Malicious prover should have probability of 1/2^N of successfully convincing
    // verifier after N rounds of the interactive proof.
    let instance = GraphPair {
        g0: Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]),
        g1: Graph::new(4, vec![(2, 1), (1, 0), (1, 3), (2, 3), (3, 2)]),
    };

    // There should be a negligible chance of the prover successfully convincing the verifier
    // in all 1000 rounds.
    assert!((0..1000).collect::<Vec<i32>>().par_iter().any(|_| {
        let mut prover = GNIProverMalicious{
            sent_guess: false,
            p: rand::thread_rng().gen(),
        };
        let mut verifier = GNIVerifier{b:false, instance: &instance};
        !run_interactive_proof(&mut prover, &mut verifier)
    }));
}

// Zero-knowledge graph non-isomorphism proof implementation

pub struct GNIProverMessage {
    // Prover guess
    b: bool,
}

pub struct GNIVerifierMessage {
    // Random permutation of either g0 or g1
    gb: Graph,
}

pub struct GNIProver<'a> {
    // Keep track of whether the interaction is done
    pub sent_guess: bool,
    pub instance: &'a GraphPair,
}

impl Prover for GNIProver<'_> {
    type ProverMessage = GNIProverMessage;
    type VerifierMessage = GNIVerifierMessage;

    fn handle(&mut self, msg: &GNIVerifierMessage) -> (GNIProverMessage, bool) {
        if self.sent_guess {
            // Send message to terminate interaction
            (GNIProverMessage { b: false }, true)
        } else {
            println!("Prover received permutation: {:?}", &msg.gb);
            // Send b = 1 if gb in the same equivalence class as g1
            self.sent_guess = true;
            (GNIProverMessage { b: are_isomorphic(&msg.gb, &self.instance.g1) }, false)
        }
    }
}

// A malicious prover can do no better than randomly guessing bit b
pub struct GNIProverMalicious {
    // Keep track of whether the interaction is done
    pub sent_guess: bool,
    // Probability of guessing 1
    pub p: f64,
}

impl Prover for GNIProverMalicious {
    type ProverMessage = GNIProverMessage;
    type VerifierMessage = GNIVerifierMessage;

    fn handle(&mut self, msg: &GNIVerifierMessage) -> (GNIProverMessage, bool) {
        if self.sent_guess {
            // Send message to terminate interaction
            (GNIProverMessage { b: false }, true)
        } else {
            println!("Prover received permutation: {:?}", &msg.gb);
            // Send b = 1 if gb in the same equivalence class as g1
            self.sent_guess = true;
            (GNIProverMessage { b: rand::thread_rng().gen_bool(self.p) }, false)
        }
    }
}

pub struct GNIVerifier<'a> {
    // Randomly chosen bit
    pub b: bool,
    pub instance: &'a GraphPair,
}

impl Verifier for GNIVerifier<'_> {
    type ProverMessage = GNIProverMessage;
    type VerifierMessage = GNIVerifierMessage;

    fn init(&mut self) -> GNIVerifierMessage {
        println!("Initializing GNI instance with the following graphs:\nG0: {:?}\nG1: {:?}.", &self.instance.g0, &self.instance.g1);
        self.b = rand::thread_rng().gen_bool(0.5);
        println!("Verifier chose graph {}.", if self.b {1} else {0});
        GNIVerifierMessage{gb: if self.b {self.instance.g1.random_permutation()} else {self.instance.g0.random_permutation()}}
    }

    fn handle(&mut self, msg: &GNIProverMessage) -> (GNIVerifierMessage, bool) {
        println!("Verifier received bit {}.", if msg.b {1} else {0});
        (GNIVerifierMessage{gb: Graph::new(0, vec![])}, msg.b == self.b)
    }
}

#[test]
fn test_gni_interactive_proof() {
    let instance = GraphPair {
        g0: Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]),
        g1: Graph::new(4, vec![(0, 2), (2, 3), (1, 3), (2, 1), (3, 0)]),
    };
    let mut prover = GNIProver{
        sent_guess: false,
        instance: &instance,
    };
    let mut verifier = GNIVerifier{b:false, instance: &instance};
    assert!(run_interactive_proof(&mut prover, &mut verifier));
}

#[test]
fn test_gni_malicious_interactive_proof() {
    // Malicious prover should have probability of 1/2^N of successfully convincing
    // verifier after N rounds of the interactive proof.
    let instance = GraphPair {
        g0: Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]),
        g1: Graph::new(4, vec![(2, 1), (1, 0), (1, 3), (2, 3), (3, 2)]),
    };

    // There should be a negligible chance of the prover successfully convincing the verifier
    // in all 1000 rounds.
    assert!((0..1000).collect::<Vec<i32>>().par_iter().any(|_| {
        let mut prover = GNIProverMalicious{
            sent_guess: false,
            p: rand::thread_rng().gen(),
        };
        let mut verifier = GNIVerifier{b:false, instance: &instance};
        !run_interactive_proof(&mut prover, &mut verifier)
    }));
}

#[derive(Clone)]
pub struct Graph {
    n: u32, // number of vertices
    edges: HashSet<(u32, u32)>, // list of directed edges
    adj: Vec<HashSet<u32>>, // adjacency list representation
}

impl Graph {
    pub fn new(n: u32, edges: Vec<(u32, u32)>) -> Graph {
        let mut graph = Graph {
            n,
            edges: edges.clone().into_iter().collect(),
            adj: vec![HashSet::new(); edges.len()],
        };
        for edge in edges.iter() {
            if cmp::max(edge.0, edge.1) >= n {
                panic!("Vertex labels must be in the range 0 to N-1. Found vertex {:?}.", cmp::max(edge.0, edge.1));
            }
            graph.adj[edge.0 as usize].insert(edge.1);
        }
        graph
    }

    fn permute(&self, isomorphism: &Vec<u32>) -> Graph {
        let mut edges: Vec<(u32, u32)> = Vec::new();
        for edge in self.edges.iter() {
            let (a, b) = (edge.0 as usize, edge.1 as usize);
            edges.push((isomorphism[a], isomorphism[b]));
        }
        Graph::new(self.n, edges)
    }

    fn random_permutation(&self) -> Graph {
        let mut isomorphism: Vec<u32> = (0..self.n).collect();
        isomorphism.shuffle(&mut thread_rng());

        self.permute(&isomorphism)
    }

    fn find_isomorphism_to(&self, other: &Graph) -> Option<Vec<u32>> {
        if self.n != other.n {
            return None;
        }
        (0..self.n).permutations(self.n as usize).find(|x| self.permute(x) == *other)
    }
}

impl fmt::Debug for Graph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Graph {{\n");
        self.adj.iter().enumerate().for_each(|(i, x)| {
            write!(f, "  {}: {:?}\n", i, x);
        });
        write!(f, "}}")
    }
}

impl PartialEq for Graph
{
    fn eq(&self, other: &Self) -> bool {
        self.edges == other.edges
    }
}

fn are_isomorphic(a: &Graph, b: &Graph) -> bool {
    if a.n != b.n {
        return false;
    }
    (0..a.n).permutations(a.n as usize).any(|x| a.permute(&x) == *b)
}

pub struct GraphPair {
    pub g0: Graph,
    pub g1: Graph,
}

#[test]
fn test_create_graph_single_edge() {
    // graph with a single edge
    let graph = Graph::new(2, vec![(0, 1)]);
    assert_eq!(graph.n, 2);
    assert!(graph.edges.contains(&(0, 1)));
    assert_eq!(graph.adj[0].len(), 1);
    assert!(graph.adj[0].contains(&1));
}

#[test]
fn test_create_graph_multi_edge() {
    // graph with a multiple edges
    let graph = Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]);
    assert_eq!(graph.n, 4);
    assert_eq!(graph.edges.len(), 5);
    assert_eq!(graph.adj[0].len(), 2);
    assert_eq!(graph.adj[1].len(), 2);
    assert_eq!(graph.adj[2].len(), 0);
    assert_eq!(graph.adj[3].len(), 1);
}

#[test]
#[should_panic]
fn test_create_invalid_graph() {
    // graph with a multiple edges
    Graph::new(4, vec![(0, 1), (1, 5), (1, 3), (0, 3), (3, 0)]);
}

#[test]
fn test_permute() {
    let perm = Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]).permute(&vec![1, 2, 3, 0]);
    let expected_perm = Graph::new(4, vec![(1, 2), (2, 3), (2, 0), (1, 0), (0, 1)]);

    assert_eq!(perm, expected_perm);
}

#[test]
fn test_are_isomorphic() {
    let graph = Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]);
    assert!((0..graph.n).permutations(graph.n as usize).any(|x| are_isomorphic(&graph, &graph.permute(&x))));
}

#[test]
fn test_random_permute() {
    // graph with a multiple edges
    let graph = Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]);
    assert!(are_isomorphic(&graph, &graph.random_permutation()))
}
