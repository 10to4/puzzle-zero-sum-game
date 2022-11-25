use ark_ff::{to_bytes, FftField};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{LabeledPolynomial, PolynomialCommitment};
use ark_std::rand::RngCore;
use ark_poly::UVPolynomial;
use ark_poly::EvaluationDomain;
use ark_poly_commit::QuerySet;
use ark_poly_commit::LabeledCommitment;
use ark_poly::Polynomial;

use crate::{
    data_structures::{Proof, Statement},
    error::Error,
    rng::FiatShamirRng,
    PROTOCOL_NAME,
};

pub fn prove<
    F: FftField,
    PC: PolynomialCommitment<F, DensePolynomial<F>>,
    FS: FiatShamirRng,
    R: RngCore,
>(
    ck: &PC::CommitterKey,
    statement: &Statement<F, PC>,
    f: &LabeledPolynomial<F, DensePolynomial<F>>,
    f_rand: &PC::Randomness,
    rng: &mut R,
) -> Result<Proof<F, PC>, Error<PC::Error>> {
    /*
        ADD YOUR CODE HERE
    */
    /*
    In the rest of protocol that is not described here, the masking polynomial is opened twice. Therefore, the masking polynomial cannot be a constant polynomial.
    */
    let mut polynomials = Vec::new();
    let mut comms = Vec::new();
    let mut rands = Vec::new();

   
    let f_comm = LabeledCommitment::new(
        "f".into(),
        statement.f.clone(),
        None,
    );
    polynomials.push(f);
    comms.push(&f_comm);
    rands.push(f_rand);
    

    let mut coeffs: Vec<F>  = f.polynomial().coeffs().into_iter().map(|coeff| coeff.clone()).collect();
    coeffs[0] = coeffs[0] + F::from(908364543u64).double().neg(); // 0x36248AFF
    let s = DensePolynomial::from_coefficients_slice(&coeffs);
    let s = LabeledPolynomial::new("s".into(), s.clone(), None, Some(1));
    let (s_commitment, s_rand) = PC::commit(&ck, &[s.clone()], Some(rng)).unwrap();
    polynomials.push(&s);
    comms.push(&s_commitment[0]);
    rands.push(&s_rand[0]);
    
    let (f_quotient, f_reminder) = f.polynomial().divide_by_vanishing_poly(statement.domain).unwrap();
    let (s_quotient, s_reminder) = s.polynomial().divide_by_vanishing_poly(statement.domain).unwrap();
    // h
    let h = f_quotient + s_quotient;

    let h = LabeledPolynomial::new("h".into(), h.clone(), None, Some(1));
    let (h_commitment, h_rand) = PC::commit(&ck, &[h.clone()], Some(rng)).unwrap();
    polynomials.push(&h);
    comms.push(&h_commitment[0]);
    rands.push(&h_rand[0]);
    
    // g
    let g = f_reminder + s_reminder;
    let g_coeffs: Vec<F> = g.coeffs().into_iter().skip(1).map(|coeff| coeff.clone()).collect();
    let g = DensePolynomial::from_coefficients_slice(&g_coeffs);
    let g = LabeledPolynomial::new("g".into(), g.clone(), Some(statement.domain.size() - 2), Some(1));
    polynomials.push(&g);
    let (g_commitment, g_rand) = PC::commit(&ck, &[g.clone()], Some(rng)).unwrap();   
    comms.push(&g_commitment[0]);
    rands.push(&g_rand[0]);

    let mut fs_rng = FS::initialize(&to_bytes![&PROTOCOL_NAME, statement].unwrap());
    fs_rng.absorb(&to_bytes![s_commitment[0].commitment().clone(), h_commitment[0].commitment().clone(), g_commitment[0].commitment().clone()].unwrap());

    let xi = F::rand(&mut fs_rng);
    // println!("[prover] xi = {}",xi);
    let opening_challenge = F::rand(&mut fs_rng);
    // println!("[prover] opening_challenge = {}",opening_challenge);
    
    let point_label = String::from("xi");
    let query_set = QuerySet::from([
        ("f".into(), (point_label.clone(), xi)),
        ("h".into(), (point_label.clone(), xi)),
        ("g".into(), (point_label.clone(), xi)),
        ("s".into(), (point_label, xi)),
    ]);

    let f_opening = f.evaluate(&xi);
    let s_opening = s.evaluate(&xi);
    let h_opening = h.evaluate(&xi);
    let g_opening = g.evaluate(&xi);

    let proof = PC::batch_open(ck, polynomials, comms, &query_set, opening_challenge, rands, Some(rng)).unwrap();

   Ok(Proof{
    f_opening,
    s: s_commitment[0].commitment().clone(),
    s_opening,
    g: g_commitment[0].commitment().clone(),
    g_opening,
    h: h_commitment[0].commitment().clone(),
    h_opening,
    pc_proof: proof,
   })
}
