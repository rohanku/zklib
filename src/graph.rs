use std::collections::HashSet;
use std::cmp;
use rand::{thread_rng, Rng, seq::SliceRandom};
use itertools::Itertools;
use crate::{Prover, Verifier, run_interactive_proof};

// Honest graph non-isomorphism prover and verifier structs and impls
struct GNIInstance {
    g0: Graph,
    g1: Graph,
}

struct GNIProverMessage {
    // Prover guess
    b: bool,
}

struct GNIVerifierMessage {
    // Random permutation of either g0 or g1
    gb: Graph,
}

struct GNIProver<'a> {
    // Keep track of whether the interaction is done
    sent_guess: bool,
    instance: &'a GNIInstance,
}

impl Prover for GNIProver<'_> {
    type ProverMessage = GNIProverMessage;
    type VerifierMessage = GNIVerifierMessage;

    fn handle(&mut self, msg: &GNIVerifierMessage) -> (GNIProverMessage, bool) {
        if self.sent_guess {
            // Send message to terminate interaction
            (GNIProverMessage { b: false }, true)
        } else {
            // Send b = 1 if gb in the same equivalence class as g1
            self.sent_guess = true;
            (GNIProverMessage { b: are_isomorphic(&msg.gb, &self.instance.g1) }, false)
        }
    }
}

struct GNIVerifier<'a> {
    // Randomly chosen bit
    b: bool,
    instance: &'a GNIInstance,
}

impl Verifier for GNIVerifier<'_> {
    type ProverMessage = GNIProverMessage;
    type VerifierMessage = GNIVerifierMessage;

    fn init(&mut self) -> GNIVerifierMessage {
        self.b = rand::thread_rng().gen_bool(0.5);
        GNIVerifierMessage{gb: if self.b {self.instance.g1.random_permutation()} else {self.instance.g0.random_permutation()}}
    }

    fn handle(&mut self, msg: &GNIProverMessage) -> (GNIVerifierMessage, bool) {
        (GNIVerifierMessage{gb: Graph::new(0, vec![])}, msg.b == self.b)
    }
}

#[test]
fn test_gni_interactive_proof() {
    let instance = GNIInstance {
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

#[derive(Debug)]
struct Graph {
    n: u32, // number of vertices
    edges: HashSet<(u32, u32)>, // list of directed edges
    adj: Vec<HashSet<u32>>, // adjacency list representation
}

impl Graph {
    fn new(n: u32, edges: Vec<(u32, u32)>) -> Graph {
        let mut graph = Graph {
            n,
            edges: edges.clone().into_iter().collect(),
            adj: vec![HashSet::new(); edges.len()],
        };
        for edge in edges.iter() {
            if cmp::max(edge.0, edge.1) >= n { panic!("Vertex labels must be in the range 0 to N-1. Found vertex {:?}.", cmp::max(edge.0, edge.1))}
            graph.adj[edge.0 as usize].insert(edge.1);
        }
        graph
    }

    fn permute(&self, shuffle: Vec<u32>) -> Graph {
        let mut edges: Vec<(u32, u32)> = Vec::new();
        for edge in self.edges.iter() {
            let (a, b) = (edge.0 as usize, edge.1 as usize);
            edges.push((shuffle[a], shuffle[b]));
        }
        Graph::new(self.n, edges)
    }

    fn random_permutation(&self) -> Graph {
        let mut shuffle: Vec<u32> = (0..self.n).collect();
        shuffle.shuffle(&mut thread_rng());

        self.permute(shuffle)
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
    (0..a.n).permutations(a.n as usize).any(|x| a.permute(x) == *b)
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
    let perm = Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]).permute(vec![1, 2, 3, 0]);
    let expected_perm = Graph::new(4, vec![(1, 2), (2, 3), (2, 0), (1, 0), (0, 1)]);

    assert_eq!(perm, expected_perm);
}

#[test]
fn test_are_isomorphic() {
    let graph = Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]);
    assert!((0..graph.n).permutations(graph.n as usize).any(|x| are_isomorphic(&graph, &graph.permute(x))));
}

#[test]
fn test_random_permute() {
    // graph with a multiple edges
    let graph = Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]);
    assert!(are_isomorphic(&graph, &graph.random_permutation()))
}
