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
    type VALUE;

    // SelfにOptionが含まれていたら、それは無視する
    fn to_vec(&self) -> Vec<Target>;

    // SelfにOptionが含まれるていたら、NoneをいれてSelfを作る
    // sizeはSelfのサイズを指定するためのoptionalな入力
    fn from_vec<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        input: &[Target],
        size: Self::SIZE,
    ) -> Self;

    // SelfにOptionが含まれるていたら、Noneの場合はwitnessを設定せず、Some(T)の場合はwitnessを設定する
    fn set_witness<F: Field>(&self, pw: &mut PartialWitness<F>, value: &Self::VALUE);

    fn register_public_inputs<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        builder.register_public_inputs(&self.to_vec());
    }
}

pub trait Statement {
    type T: RecursiveTarget;

    fn build_circuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    ) -> (CircuitData<F, C, D>, Self::T);

    fn generate_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        data: &CircuitData<F, C, D>,
        target: &Self::T,
        value: &<Self::T as RecursiveTarget>::VALUE,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        <Self::T as RecursiveTarget>::set_witness(target, &mut pw, value);
        data.prove(pw)
    }
}
