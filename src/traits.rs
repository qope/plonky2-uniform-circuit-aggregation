use anyhow::Result;
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitData, config::GenericConfig,
        proof::ProofWithPublicInputs,
    },
};

pub trait RecursiveTarget {
    type SIZE;
    type VALUE<F>;

    fn to_vec(&self) -> Vec<Target>;

    fn from_vec<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        input: &[Target],
        size: &Self::SIZE,
    ) -> Self;

    fn set_witness<F: Field>(&self, pw: &mut PartialWitness<F>, value: &Self::VALUE<F>);

    fn register_public_inputs<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        builder.register_public_inputs(&self.to_vec());
    }
}

pub trait Provable: RecursiveTarget {
    fn build_circuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    ) -> (CircuitData<F, C, D>, Self);

    fn generate_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        &self,
        data: &CircuitData<F, C, D>,
        value: &<Self as RecursiveTarget>::VALUE<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        <Self as RecursiveTarget>::set_witness(&self, &mut pw, value);
        data.prove(pw)
    }

    fn decode_statement_target<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        public_inputs: &[Target],
        num_targets_per_statement: usize,
        statement_size: &<Self as RecursiveTarget>::SIZE,
    ) -> Vec<Self>
    where
        Self: Sized,
    {
        assert!(public_inputs.len() % num_targets_per_statement == 0);
        public_inputs
            .chunks(num_targets_per_statement)
            .map(|statement_vec| {
                <Self as RecursiveTarget>::from_vec(builder, statement_vec, statement_size)
            })
            .collect()
    }
}
