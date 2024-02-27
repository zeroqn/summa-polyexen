use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
};
use summa_solvency::chips::merkle_sum_tree::{MerkleSumTreeChip, MerkleSumTreeConfig};

#[derive(Clone)]
pub struct SummaMSTChipConfig {
    mst_config: MerkleSumTreeConfig,
    advices: [Column<Advice>; 3],
    instances: [Column<Instance>; 3],
}

impl SummaMSTChipConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let advices: [Column<Advice>; 3] = std::array::from_fn(|_| meta.advice_column());
        let instances: [Column<Instance>; 3] = std::array::from_fn(|_| meta.instance_column());
        let selectors: [Selector; 2] = std::array::from_fn(|_| meta.selector());

        let mst_config = MerkleSumTreeChip::<1>::configure(meta, advices, selectors);
        for col in &advices {
            meta.enable_equality(*col);
        }
        for col in &instances {
            meta.enable_equality(*col);
        }

        Self {
            mst_config,
            advices,
            instances,
        }
    }
}

pub struct SummaMSTChip {
    current_hash: Fr,
    sibling_hash: Fr,
    swap_bit: Fr,
}

impl SummaMSTChip {
    #[allow(dead_code)]
    pub fn init_empty() -> Self {
        Self {
            current_hash: Fr::zero(),
            sibling_hash: Fr::zero(),
            swap_bit: Fr::zero(),
        }
    }
}

impl Circuit<Fr> for SummaMSTChip {
    type Config = SummaMSTChipConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            current_hash: Fr::zero(),
            sibling_hash: Fr::zero(),
            swap_bit: Fr::zero(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        SummaMSTChipConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> std::result::Result<(), Error> {
        let mst_chip = MerkleSumTreeChip::<2>::construct(config.mst_config);

        let current_hash = layouter.assign_region(
            || "assign current hash",
            |mut region| {
                region.assign_advice(
                    || "current hash",
                    config.advices[0],
                    0,
                    || Value::known(self.current_hash),
                )
            },
        )?;

        let sibling_hash = layouter.assign_region(
            || "assign sibling hash",
            |mut region| {
                region.assign_advice(
                    || "sibling hash",
                    config.advices[1],
                    0,
                    || Value::known(self.sibling_hash),
                )
            },
        )?;

        let swap_bit = layouter.assign_region(
            || "assign swap bit",
            |mut region| {
                region.assign_advice(
                    || "swap bit",
                    config.advices[2],
                    0,
                    || Value::known(self.swap_bit),
                )
            },
        )?;

        let (next_left_hash, next_right_hash) = mst_chip.swap_hashes_per_level(
            layouter.namespace(|| "swap"),
            &current_hash,
            &sibling_hash,
            &swap_bit,
        )?;

        layouter.constrain_instance(next_left_hash.cell(), config.instances[0], 0)?;
        layouter.constrain_instance(next_right_hash.cell(), config.instances[1], 0)?;
        layouter.constrain_instance(swap_bit.cell(), config.instances[2], 0)?;

        Ok(())
    }
}
