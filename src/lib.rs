use itertools::Itertools;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use rayon::{prelude::ParallelIterator, slice::ParallelSlice};

pub mod traits;

pub fn add_recursive_constraint<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    inner_data: &CircuitData<F, C, D>,
) -> ProofWithPublicInputsTarget<D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let vt = builder.constant_verifier_data(&inner_data.verifier_only);
    let proof_t = builder.add_virtual_proof_with_pis(&inner_data.common);
    builder.verify_proof::<C>(&proof_t, &vt, &inner_data.common);
    proof_t
}

pub fn generate_aggregation_proofs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    proofs: &[ProofWithPublicInputs<F, C, D>],
    setup: &AggregationSetUp<F, C, D>,
) -> ProofWithPublicInputs<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let mut proofs = padd_proofs(setup.n, setup.alignment.clone(), proofs);
    setup
        .alignment
        .iter()
        .zip(setup.circuits_data.iter())
        .zip(setup.proof_t_vecs.iter())
        .for_each(|((&arity, data), proof_targets)| {
            let agg_proofs: Vec<_> = proofs
                .par_chunks(arity)
                .map(|proof_chunk| {
                    let mut pw = PartialWitness::<F>::new();
                    proof_chunk
                        .iter()
                        .zip(proof_targets)
                        .for_each(|(proof, proof_t)| pw.set_proof_with_pis_target(proof_t, proof));
                    data.prove(pw).unwrap()
                })
                .collect();
            proofs = agg_proofs;
        });
    assert!(proofs.len() == 1, "final proof should be one");
    proofs[0].clone()
}

fn padd_proofs<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    n: usize,
    alignment: Vec<usize>,
    proofs: &[ProofWithPublicInputs<F, C, D>],
) -> Vec<ProofWithPublicInputs<F, C, D>> {
    // calc product of alignment
    let product: usize = alignment.iter().product();
    assert!(n <= product);

    // padding
    let mut padded_proofs = proofs.to_vec();
    let last_proof = proofs.last().unwrap().clone();
    padded_proofs.extend(vec![last_proof; product - n]);
    padded_proofs
}

pub struct AggregationSetUp<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub n: usize,
    pub alignment: Vec<usize>,
    pub circuits_data: Vec<CircuitData<F, C, D>>,
    pub proof_t_vecs: Vec<Vec<ProofWithPublicInputsTarget<D>>>,
}

pub fn build_circuits<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    n: usize,
    config: &CircuitConfig,
    base_circuit_data: &CircuitData<F, C, D>,
    alignment: Vec<usize>,
) -> AggregationSetUp<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let mut circuits_data = vec![];
    let mut proof_t_vecs = vec![];

    alignment.iter().enumerate().for_each(|(i, &arity)| {
        let inner_data = {
            if i == 0 {
                base_circuit_data
            } else {
                circuits_data.last().unwrap()
            }
        };
        let mut builder = CircuitBuilder::new(config.clone());
        let proofs_t = (0..arity)
            .map(|_| add_recursive_constraint(&mut builder, inner_data))
            .collect_vec();
        let statement_vec = proofs_t
            .iter()
            .cloned()
            .flat_map(|proof_t| proof_t.public_inputs)
            .collect_vec();
        builder.register_public_inputs(&statement_vec);
        let data = builder.build::<C>();
        circuits_data.push(data);
        proof_t_vecs.push(proofs_t);
    });
    AggregationSetUp {
        n,
        alignment,
        circuits_data,
        proof_t_vecs,
    }
}
