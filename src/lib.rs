mod graph;

pub trait Prover {
    type ProverMessage;
    type VerifierMessage;

    // The prover should take in a message from the verifier and return a message
    // to send to the verifier as well as a 'done' flag denoting whether the interaction
    // is complete.
    fn handle(&mut self, msg: &Self::VerifierMessage) -> (Self::ProverMessage, bool);
}

pub trait Verifier {
    type ProverMessage;
    type VerifierMessage;

    // The verifier always sends the first message, although if necessary it can
    // send a dummy message to allow the prover to begin the interaction.
    fn init(&mut self) -> Self::VerifierMessage;

    // The verifier should take in a message from the prover and return a message
    // to send to the prover as well as an 'accept' flag denoting whether it accepts or not.
    // If the flag is ever set to true, the verifier accepts the proof.
    fn handle(&mut self, msg: &Self::ProverMessage) -> (Self::VerifierMessage, bool);
}

pub fn run_interactive_proof<T, U>(prover: &mut dyn Prover<ProverMessage = T, VerifierMessage = U>, verifier: &mut dyn Verifier<ProverMessage = T, VerifierMessage = U>) -> bool{

    let mut verifier_msg = verifier.init();
    let mut accept = false;

    // Run interaction until prover sets 'done' flag to true, prover must send last message
    while let (prover_msg, false) = prover.handle(&verifier_msg) {
        let x = verifier.handle(&prover_msg);
        verifier_msg = x.0;
        accept = x.1;
    }

    accept
}