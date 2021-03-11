use vade_evan_bbs::application::{issuer::Issuer, prover::Prover};

#[test]
fn test_issuance_workflow() {
    // Create credential proposal
    let proposal = Prover::propose_credential(/*arguments*/);

    // Create credential offering
    let offering = Issuer::offer_credential(/*arguments*/);

    // Create credential request

    // Issue credential

    // Finish credential
}
