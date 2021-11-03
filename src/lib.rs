use tokio::sync::mpsc;

pub trait Prover {
    type ProverState;
    type VerifierMessage;
    type ProverMessage;

    fn init(&self, v_channel: mpsc::Sender<Self::ProverMessage>) -> mpsc::Sender<Self::VerifierMessage>;
    fn handle(&self, state: Self::ProverState, msg: Self::VerifierMessage) -> Self::ProverMessage;
}

pub trait Verifier {
    type VerifierState;
    type VerifierMessage;
    type ProverMessage;

    fn init(&self) -> mpsc::Sender<Self::ProverMessage>;
    fn handle(&self, state: Self::VerifierState, msg: Self::ProverMessage) -> Self::VerifierMessage;
}

use std::collections::HashSet;
use std::cmp;
use rand::thread_rng;
use rand::seq::SliceRandom;
use itertools::Itertools;

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

    fn perm(&self, shuffle: Vec<u32>) -> Graph {
        let mut edges: Vec<(u32, u32)> = Vec::new();
        for edge in self.edges.iter() {
            let (a, b) = (edge.0 as usize, edge.1 as usize);
            edges.push((shuffle[a], shuffle[b]));
        }
        Graph::new(self.n, edges)
    }

    fn random_perm(&self) -> Graph {
        let mut shuffle: Vec<u32> = (0..self.n).collect();
        shuffle.shuffle(&mut thread_rng());

        self.perm(shuffle)
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
    (0..a.n).permutations(a.n as usize).any(|x| a.perm(x) == *b)
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
    let graph = Graph::new(4, vec![(0, 1), (1, 5), (1, 3), (0, 3), (3, 0)]);
}

#[test]
fn test_is_isomorphic() {

}

#[test]
fn test_permutation() {
    // graph with a multiple edges
    let graph = Graph::new(4, vec![(0, 1), (1, 2), (1, 3), (0, 3), (3, 0)]);
    assert!(are_isomorphic(&graph, &graph.random_perm()))
}
