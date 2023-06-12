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
            println!("arity: {}", arity);
            println!("proofs len: {}", proofs.len());
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

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{
            extension::Extendable, goldilocks_field::GoldilocksField, ops::Square, types::Field,
        },
        hash::hash_types::RichField,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rayon::prelude::{IntoParallelIterator, ParallelIterator};

    use crate::{
        build_circuits, generate_aggregation_proofs,
        traits::{Provable, RecursiveTarget},
    };

    pub struct SquareTarget {
        pub x: Target,
        pub x_sq: Target,
    }

    pub struct SquareWitness<F> {
        pub x: F,
        pub x_sq: F,
    }

    impl RecursiveTarget for SquareTarget {
        type SIZE = ();
        type VALUE<F> = SquareWitness<F>;

        fn to_vec(&self) -> Vec<Target> {
            vec![self.x, self.x_sq]
        }
        fn from_vec<F: RichField + Extendable<D>, const D: usize>(
            _builder: &mut CircuitBuilder<F, D>,
            input: &[Target],
            _size: &Self::SIZE,
        ) -> Self {
            assert!(input.len() == 2);
            let x = input[0];
            let x_sq = input[1];
            SquareTarget { x, x_sq }
        }
        fn set_witness<F: Field>(&self, pw: &mut PartialWitness<F>, value: &SquareWitness<F>) {
            pw.set_target(self.x, value.x);
            pw.set_target(self.x_sq, value.x_sq);
        }
    }

    impl Provable for SquareTarget {
        fn build_circuit<
            F: RichField + Extendable<D>,
            C: GenericConfig<D, F = F>,
            const D: usize,
        >() -> (CircuitData<F, C, D>, Self) {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::new(config);

            let x = builder.add_virtual_target();
            let x_sq = builder.square(x);

            let target = SquareTarget { x, x_sq };
            let data = builder.build::<C>();
            (data, target)
        }
    }

    #[test]
    fn test_proof_aggregation() {
        type F = GoldilocksField;
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        let n = 10;
        let alignment = vec![2, 3, 2];

        let config = CircuitConfig::standard_recursion_config();
        let (base_data, base_target) = SquareTarget::build_circuit::<F, C, D>();
        let setup = build_circuits(n, &config, &base_data, alignment);

        let base_proofs = (0..n)
            .into_par_iter()
            .map(|i| {
                let value = SquareWitness {
                    x: F::from_canonical_usize(i),
                    x_sq: F::from_canonical_usize(i).square(),
                };
                base_target.generate_proof(&base_data, &value).unwrap()
            })
            .collect::<Vec<_>>();
        let _agg_proof = generate_aggregation_proofs(&base_proofs, &setup);
    }
}
