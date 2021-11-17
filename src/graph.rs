use std::{collections::HashSet, cmp, fmt};
use rand::{thread_rng, Rng, seq::SliceRandom};
use itertools::Itertools;
use rayon::prelude::*;
use crate::{Prover, Verifier, run_interactive_proof};

// ************ Zero-knowledge graph isomorphism proof implementation ************

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
    // Random permutation sent to verifier
    pub random_perm: Graph,
    pub instance: &'a GraphPair,
}

impl Prover for GIProver<'_> {
    type ProverMessage = GIProverMessage;
    type VerifierMessage = GIVerifierMessage;

    fn handle(&mut self, msg: &GIVerifierMessage) -> (GIProverMessage, bool) {
        self.r += 1;
        match self.r {
            // During the first round, the prover sends random permutation of G0 to the verifier
            1 => { self.random_perm = self.instance.g0.random_permutation(); (GIProverMessage::Graph(self.random_perm.clone()), false) },
            // During the second round, the prover sends an isomorphism from the random permutation to a graph of verifier's choosing
            2 => (GIProverMessage::Isomorphism(self.random_perm.find_isomorphism_to(if msg.b {&self.instance.g1} else {&self.instance.g0}).unwrap()), false),
            // After sending an isomorphism, the prover sends a message to terminate the interaction
            _ => (GIProverMessage::Done, true),
        }
    }
}

// A malicious prover can do no better than randomly guessing bit b and sending a permutation of the corresponding graph
pub struct GIProverMalicious<'a> {
    // Keep track of round number
    pub r: u32,
    // Random isomorphism of chosen graph, result of applying this isomorphism sent to verifier
    pub isomorphism: Vec<u32>,
    pub instance: &'a GraphPair,
    // Probability of guessing 1
    pub p: f64,
}

impl Prover for GIProverMalicious<'_> {
    type ProverMessage = GIProverMessage;
    type VerifierMessage = GIVerifierMessage;

    fn handle(&mut self, msg: &GIVerifierMessage) -> (GIProverMessage, bool) {
        self.r += 1;
        match self.r {
            // In the first round, the prover guesses a random bit and sends a random permutation of the corresponding graph
            1 => {
                let b = rand::thread_rng().gen_bool(0.5);
                println!("Prover guessed bit {}.", if b {1} else {0});
                let graph = if b {self.instance.g1.clone()} else {self.instance.g0.clone()};
                self.isomorphism = (0..graph.n).collect::<Vec<u32>>();
                self.isomorphism.shuffle(&mut thread_rng());
                (GIProverMessage::Graph(graph.permute(&self.isomorphism)), false)
            },
            // The prover can only find an isomorphism to the graph it chose, so it sends it regardless of what the verifier chooses
            2 => (GIProverMessage::Isomorphism(invert_isomorphism(&self.isomorphism)), false),
            // After sending an isomorphism, the prover sends a message to terminate the interaction
            _ => (GIProverMessage::Done, true),
        }
    }
}

pub struct GIVerifier<'a> {
    // Keep track of round number
    pub r: u32,
    // Randomly chosen bit
    pub b: bool,
    // Random permutation received from prover
    pub random_perm: Graph,
    pub instance: &'a GraphPair,
}

impl Verifier for GIVerifier<'_> {
    type ProverMessage = GIProverMessage;
    type VerifierMessage = GIVerifierMessage;

    fn init(&mut self) -> GIVerifierMessage {
        println!("Initializing GI instance with graphs {:?} and {:?}.", &self.instance.g0, &self.instance.g1);
        GIVerifierMessage{ b: false }
    }

    fn handle(&mut self, msg: &GIProverMessage) -> (GIVerifierMessage, bool) {
        self.r += 1;
        match self.r {
            1 => {
                if let GIProverMessage::Graph(random_perm) = msg {
                    println!("Verifier received permutation {:?}.", random_perm);
                    self.random_perm = random_perm.clone();
                    self.b = rand::thread_rng().gen_bool(0.5);
                    println!("Verifier chose graph {}.", if self.b { 1 } else { 0 });
                    (GIVerifierMessage { b: self.b }, false)
                } else {
                    panic!("Prover did not send a valid graph on round 1!")
                }
            },
            _ => {
                if let GIProverMessage::Isomorphism(isomorphism) = msg {
                    println!("Verifier received isomorphism {:?}.", isomorphism);
                    (GIVerifierMessage { b: self.b }, &self.random_perm.permute(&isomorphism) == if self.b {&self.instance.g1} else {&self.instance.g0})
                } else {
                    panic!("Prover did not send a valid isomorphism on round 2!")
                }

        }
    }
    }
}

#[test]
fn test_gi_interactive_proof() {
    let instance = GraphPair {
        g0: Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]),
        g1: Graph::new(4, vec![(2, 1), (1, 0), (1, 3), (2, 3), (3, 2)]),
    };
    let mut prover = GIProver{
        r: 0,
        random_perm: Graph::new(0, Vec::new()),
        instance: &instance,
    };
    let mut verifier = GIVerifier{
        r: 0,
        b: false,
        random_perm: Graph::new(0, Vec::new()),
        instance: &instance,
    };
    // Since the proof has perfect completeness, an honest prover should always be able to prove that the graphs are in GI.
    assert!(run_interactive_proof(&mut prover, &mut verifier));
}

#[test]
fn test_gi_malicious_interactive_proof() {
    // Malicious prover should have probability of 1/2^N of successfully convincing
    // verifier after N rounds of the interactive proof.
    let N = 1000;
    let instance = GraphPair {
        g0: Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]),
        g1: Graph::new(4, vec![(0, 2), (2, 3), (1, 3), (2, 1), (3, 0)]),
    };

    // There should be a negligible chance of the prover successfully convincing the verifier
    // in all 1000 rounds.
    let successes = (0..N).collect::<Vec<i32>>().par_iter().filter(|_| {
        let mut prover = GIProverMalicious{
            r: 0,
            isomorphism: Vec::new(),
            instance: &instance,
            p: 0.5,
        };
        let mut verifier = GIVerifier{
            r: 0,
            b: false,
            random_perm: Graph::new(0, Vec::new()),
            instance: &instance,
        };
        run_interactive_proof(&mut prover, &mut verifier)
    }).count();

    println!("Malicious GI prover succeeded {} out of {} times.", successes, N);

    assert!(successes != N as usize);
}

// ************ Zero-knowledge graph non-isomorphism proof implementation ************

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
            // If the prover already sent a guess, they send a message to terminate the interaction
            (GNIProverMessage { b: false }, true)
        } else {
            println!("Prover received permutation: {:?}.", &msg.gb);
            // The prover sends b = 1 if Gb is in the same equivalence class as G1
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
            // If the prover already sent a guess, they send a message to terminate the interaction
            (GNIProverMessage { b: false }, true)
        } else {
            println!("Prover received permutation: {:?}.", &msg.gb);
            // The malicious prover sends a random bit b that is 1 with probability p
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
        // The verifier randomly chooses a random graph to randomly permute and send to the prover
        self.b = rand::thread_rng().gen_bool(0.5);
        println!("Verifier chose graph {}.", if self.b {1} else {0});
        GNIVerifierMessage{gb: if self.b {self.instance.g1.random_permutation()} else {self.instance.g0.random_permutation()}}
    }

    fn handle(&mut self, msg: &GNIProverMessage) -> (GNIVerifierMessage, bool) {
        println!("Verifier received bit {}.", if msg.b {1} else {0});
        // The verifier accepts the proof if the prover correctly guesses bit b
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
    // Since the proof has perfect completeness, an honest prover should always be able to prove that the graphs are in GNI.
    assert!(run_interactive_proof(&mut prover, &mut verifier));
}

#[test]
fn test_gni_malicious_interactive_proof() {
    // Malicious prover should have probability of 1/2^N of successfully convincing
    // verifier after N rounds of the interactive proof.
    let N = 1000;
    let instance = GraphPair {
        g0: Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]),
        g1: Graph::new(4, vec![(2, 1), (1, 0), (1, 3), (2, 3), (3, 2)]),
    };

    // There should be a negligible chance of the prover successfully convincing the verifier
    // in all 1000 rounds.
    let successes = (0..N).collect::<Vec<i32>>().par_iter().filter(|_| {
        let mut prover = GNIProverMalicious{
            sent_guess: false,
            p: 0.5,
        };
        let mut verifier = GNIVerifier{b:false, instance: &instance};
        run_interactive_proof(&mut prover, &mut verifier)
    }).count();

    println!("Malicious GI prover succeeded {} out of {} times.", successes, N);

    assert!(successes != N as usize);
}

// ************ Graph and additional function implementations ************

#[derive(Clone)]
pub struct Graph {
    // Number of vertices
    n: u32,
    // List of directed edges
    edges: HashSet<(u32, u32)>,
    // Adjacency list representation
    adj: Vec<HashSet<u32>>,
}

impl Graph {
    pub fn new(n: u32, edges: Vec<(u32, u32)>) -> Graph {
        let mut graph = Graph {
            n,
            edges: edges.clone().into_iter().collect(),
            adj: vec![HashSet::new(); edges.len()],
        };
        // The constructor builds the adjacency list from the provided list of directed edges
        for edge in edges.iter() {
            if cmp::max(edge.0, edge.1) >= n {
                panic!("Vertex labels must be in the range 0 to N-1. Found vertex {:?}.", cmp::max(edge.0, edge.1));
            }
            graph.adj[edge.0 as usize].insert(edge.1);
        }
        graph
    }

    // Apply given isomorphism to self and return resulting graph
    fn permute(&self, isomorphism: &Vec<u32>) -> Graph {
        let mut edges: Vec<(u32, u32)> = Vec::new();
        for edge in self.edges.iter() {
            let (a, b) = (edge.0 as usize, edge.1 as usize);
            edges.push((isomorphism[a], isomorphism[b]));
        }
        Graph::new(self.n, edges)
    }

    // Apply random isomorphism to self and return resulting graph
    fn random_permutation(&self) -> Graph {
        let mut isomorphism: Vec<u32> = (0..self.n).collect();
        isomorphism.shuffle(&mut thread_rng());
        self.permute(&isomorphism)
    }

    // Finds isomorphism that takes self to other
    fn find_isomorphism_to(&self, other: &Graph) -> Option<Vec<u32>> {
        if self.n != other.n {
            return None;
        }
        (0..self.n).permutations(self.n as usize).find(|x| self.permute(x) == *other)
    }
}

impl fmt::Debug for Graph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = String::new();
        output.push_str("Graph {{\n");
        self.adj.iter().enumerate().for_each(|(i, x)| {
            output.push_str(&format!("  {}: {:?}\n", i, x));
        });
        output.push_str("}}");
        write!(f, "{}", output)
    }
}

impl PartialEq for Graph
{
    fn eq(&self, other: &Self) -> bool {
        self.edges == other.edges
    }
}

fn are_isomorphic(a: &Graph, b: &Graph) -> bool {
    // First checks if the graphs have an equal number of vertices and edges, then searches through all possible permutations
    if a.n != b.n || a.edges.len() != b.edges.len(){
        return false;
    }
    (0..a.n).permutations(a.n as usize).any(|x| a.permute(&x) == *b)
}

fn invert_isomorphism(isomorphism: &Vec<u32>) -> Vec<u32> {
    let mut inverted = vec![0; isomorphism.len()];
    isomorphism.iter().enumerate().for_each(|(i, x)| {
        inverted[*x as usize] = i as u32;
    });
    inverted
}

pub struct GraphPair {
    pub g0: Graph,
    pub g1: Graph,
}

#[test]
fn test_create_graph_single_edge() {
    let graph = Graph::new(2, vec![(0, 1)]);
    assert_eq!(graph.n, 2);
    assert!(graph.edges.contains(&(0, 1)));
    assert_eq!(graph.adj[0].len(), 1);
    assert!(graph.adj[0].contains(&1));
}

#[test]
fn test_create_graph_multi_edge() {
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
    // Vertex labels must be in the range 0 to N-1, inclusive
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
    // All permutations of the graph should be isomorphic to it
    assert!((0..graph.n).permutations(graph.n as usize).any(|x| are_isomorphic(&graph, &graph.permute(&x))));
}

#[test]
fn test_random_permute() {
    let graph = Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]);
    // Any random permutation of the graph should be isomorphic to it
    assert!(are_isomorphic(&graph, &graph.random_permutation()))
}
