use std::time::Instant;

use itertools::Itertools;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, ops::Square, types::Field},
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
use plonky2_uniform_circuit_aggregation::{
    add_recursive_constraint, build_circuits, generate_aggregation_proofs,
    traits::{Provable, RecursiveTarget},
};
use rayon::{
    prelude::{IntoParallelRefIterator, ParallelIterator},
    ThreadPoolBuilder,
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
    fn build_circuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    ) -> (CircuitData<F, C, D>, Self) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);

        let x = builder.add_virtual_target();
        let x_sq = builder.square(x);

        let target = SquareTarget { x, x_sq };
        let data = builder.build::<C>();
        (data, target)
    }
}

fn constant_strategy(n: usize, arity: usize) -> Vec<usize> {
    let mut i = 1usize;
    while arity.pow(i as u32) < n {
        i += 1;
    }
    vec![arity; i]
}

fn main() {
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    let n = 100;
    let num_targets_per_statement = 2;
    let alignment = constant_strategy(n, 10);
    dbg!(alignment.clone());

    // set number of threads
    let num_threads = 8;
    ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .unwrap();

    // setup
    let config = CircuitConfig::standard_recursion_config();
    let (base_data, base_target) = SquareTarget::build_circuit::<F, C, D>();
    let setup = build_circuits(n, &config, &base_data, alignment);

    // generate witness
    let witness = (0..n)
        .map(|i| SquareWitness {
            x: F::from_canonical_usize(i),
            x_sq: F::from_canonical_usize(i).square(),
        })
        .collect_vec();

    // generate base proofs
    let base_proofs = witness
        .par_iter()
        .map(|w| base_target.generate_proof(&base_data, w).unwrap())
        .collect::<Vec<_>>();

    // generate aggregation proof
    let now = Instant::now();
    let final_proof = generate_aggregation_proofs(&base_proofs, &setup);
    println!("Aggregation time: {:?}", now.elapsed());

    // verify
    let final_circuit = setup.circuits_data.last().unwrap();
    final_circuit.verify(final_proof.clone()).unwrap();

    // use the final proof in recursive circuit
    {
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let proof_t = add_recursive_constraint(&mut builder, final_circuit);

        let statements_t = <SquareTarget as Provable>::decode_statement_target::<F, C, D>(
            &mut builder,
            &proof_t.public_inputs,
            num_targets_per_statement,
            &(),
        );

        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&proof_t, &final_proof);

        // for_test is used to check the correctness of the proof
        witness.iter().zip(statements_t).for_each(|(w, t)| {
            t.set_witness(&mut pw, w);
        });

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }
}
