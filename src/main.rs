#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::File,
    io::{self, Write},
    path::Path,
};

use env_logger::Env;
use halo2_proofs::{halo2curves::bn256::Fr, plonk::Circuit};
use num_bigint::BigUint;
use polyexen::{
    analyze::{bound_base, find_bounds_poly, Analysis, Bound},
    expr::{Expr, ExprDisplay, Var},
    plaf::{
        frontends::halo2::get_plaf, Cell, CellDisplay, Lookup, Plaf, PlafDisplayBaseTOML,
        PlafDisplayFixedCSV,
    },
};

mod circuit;

// Base on https://github.com/ed255/polyexen-demo/blob/main/src/bin/demo.rs
fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // let c = circuit::SummaMSTChip::init_empty();
    let c = summa_solvency::circuits::merkle_sum_tree::MstInclusionCircuit::<4, 2, 4>::init_empty();
    let k = 12;

    let analysis = do_circuit_analysis(k, &c);
    analysis.write_files("mst").unwrap();
}

#[derive(Default, Debug)]
struct VarPointers {
    polys: Vec<usize>,
    lookups: Vec<usize>,
    copys: Vec<usize>,
}

fn do_circuit_analysis(k: u32, c: &impl Circuit<Fr>) -> AnalysisResult {
    let mut plaf = get_plaf(k, c).unwrap();
    plaf.simplify();

    let p = BigUint::parse_bytes(b"100000000000000000000000000000000", 16).unwrap()
        - BigUint::from(159u64);
    let mut analysis: Analysis<Cell> = Analysis::new();

    let cell_fmt =
        |f: &mut fmt::Formatter<'_>, c: &Cell| write!(f, "{}", CellDisplay { c, plaf: &plaf });
    let mut var_map: HashMap<_, VarPointers> = HashMap::new();

    // Output poly var -> raw poly index
    let mut raw_polys = Vec::new();
    for offset in 0..plaf.info.num_rows {
        for poly in &plaf.polys {
            let mut exp = plaf.resolve(&poly.exp, offset);
            exp.simplify(&p);
            if exp.is_zero() {
                continue;
            }
            log::trace!(
                "\"{}\": {}",
                poly.name,
                ExprDisplay {
                    e: &exp,
                    var_fmt: cell_fmt
                }
            );
            // Fill bounds in analysis.vars_attrs
            find_bounds_poly(&exp, &p, &mut analysis);

            for var in exp.vars() {
                let pointers = var_map.entry(var).or_insert(VarPointers::default());
                pointers.polys.push(raw_polys.len()); // push poly index in raw_polys
            }
            raw_polys.push(ResolvedPoly {
                name: poly.name.clone(),
                expr: exp,
            });
        }
    }

    let bound_base = bound_base(&p);
    let mut var_bounds = Vec::new();
    for (cell, attrs) in &analysis.vars_attrs {
        if attrs.bound == bound_base {
            continue;
        }
        log::trace!(
            "{} bound {:?}",
            CellDisplay {
                c: cell,
                plaf: &plaf
            },
            attrs.bound
        );

        var_bounds.push((cell.clone(), attrs.bound.clone()));
    }

    let mut raw_lookups = Vec::new();
    for offset in 0..plaf.info.num_rows {
        for (lookup_num, lookup) in plaf.lookups.iter().enumerate() {
            let Lookup { name, exps } = lookup;
            let exps_lhs: Vec<_> = exps
                .0
                .iter()
                .map(|exp| {
                    let mut exp = plaf.resolve(&exp, offset);
                    exp.simplify(&plaf.info.p);
                    exp
                })
                .collect();
            if exps_lhs.iter().all(|exp| exp.is_zero()) {
                continue;
            }
            for exp in &exps_lhs {
                for var in exp.vars() {
                    let pointers = var_map.entry(var).or_insert(VarPointers::default());
                    pointers.lookups.push(raw_lookups.len()); // push lookup index
                }
            }
            raw_lookups.push(ResolvedLookup {
                name: name.clone(),
                exprs_num: (exps_lhs.clone(), lookup_num),
            });
            log::trace!("[");
            for (i, exp) in exps_lhs.iter().enumerate() {
                if i != 0 {
                    log::trace!(", ")
                }
                log::trace!(
                    "{}",
                    ExprDisplay {
                        e: &exp,
                        var_fmt: cell_fmt
                    },
                );
            }
            log::trace!("] in [");
            for (i, exp) in exps.1.iter().enumerate() {
                if i != 0 {
                    log::trace!(", ")
                }
                log::trace!(
                    "{}",
                    ExprDisplay {
                        e: &exp,
                        var_fmt: |f, v| plaf.fmt_var(f, v)
                    },
                );
            }
            log::trace!("] # {}", name);
        }
    }

    let mut raw_copys = Vec::new();
    for copy in &plaf.copys {
        let (column_a, column_b) = copy.columns;
        for offset in &copy.offsets {
            let cell_a = Cell {
                column: column_a,
                offset: offset.0,
            };
            let cell_b = Cell {
                column: column_b,
                offset: offset.1,
            };

            log::trace!(
                "{} - {}",
                CellDisplay {
                    c: &cell_a,
                    plaf: &plaf
                },
                CellDisplay {
                    c: &cell_b,
                    plaf: &plaf
                }
            );

            let pointers = var_map
                .entry(cell_a.clone())
                .or_insert(VarPointers::default());
            pointers.copys.push(raw_copys.len());
            let pointers = var_map
                .entry(cell_b.clone())
                .or_insert(VarPointers::default());
            pointers.copys.push(raw_copys.len());
            raw_copys.push((cell_a, cell_b));
        }
    }

    let mut copy_sets = Vec::new();
    let mut cleared = HashSet::new();
    let mut dup_vars_count = 0;
    for (index, (cell_main, cell_b)) in raw_copys.iter().enumerate() {
        if cleared.contains(&index) {
            continue;
        }
        cleared.insert(index);
        let mut next = vec![cell_b.clone()];
        let mut copy_set = HashSet::new();
        while let Some(cell) = next.pop() {
            if cell == *cell_main {
                continue;
            }
            copy_set.insert(cell.clone());
            if let Some(pointers) = var_map.get(&cell) {
                for copy_index in &pointers.copys {
                    if cleared.contains(copy_index) {
                        continue;
                    }
                    cleared.insert(*copy_index);
                    let (cell_a, cell_b) = raw_copys[*copy_index].to_owned();
                    next.push(cell_a);
                    next.push(cell_b);
                }
            }
        }
        dup_vars_count += copy_set.len();
        copy_sets.push((cell_main, copy_set));
    }
    log::debug!("dup_vars_count={}", dup_vars_count);

    for copy in &copy_sets {
        log::trace!(
            "{} <- [",
            CellDisplay {
                c: copy.0,
                plaf: &plaf
            }
        );
        for (i, copy_cell) in copy.1.iter().enumerate() {
            if i != 0 {
                log::trace!(", ");
            }
            log::trace!(
                "{}",
                CellDisplay {
                    c: copy_cell,
                    plaf: &plaf
                }
            );
        }
        log::trace!("]");
    }

    // Apply copy constraint replacements
    for (cell_main, copy_set) in &copy_sets {
        for cell in copy_set {
            if let Some(pointers) = var_map.get(cell) {
                for poly_index in &pointers.polys {
                    let poly = raw_polys.get_mut(*poly_index).unwrap();
                    poly.expr
                        .replace_var(cell, &Expr::Var((*cell_main).to_owned()));
                }
                for lookup_index in &pointers.lookups {
                    let lookup = raw_lookups.get_mut(*lookup_index).unwrap();
                    for exp in lookup.exprs_num.0.iter_mut() {
                        exp.replace_var(cell, &Expr::Var((*cell_main).to_owned()));
                    }
                }
            }
        }
    }

    AnalysisResult {
        polys: raw_polys,
        lookups: raw_lookups,
        var_bounds,
        plaf,
    }
}

trait ExprReplaceVar<V: Var> {
    fn replace_var(&mut self, v: &V, replacement: &Expr<V>);
}

impl<V: Var> ExprReplaceVar<V> for Expr<V> {
    fn replace_var(&mut self, v: &V, replacement: &Expr<V>) {
        use Expr::*;
        match self {
            Const(_) => {}
            Var(_) => {
                *self = replacement.clone();
            }
            Neg(e) => e.replace_var(v, replacement),
            Pow(e, _) => e.replace_var(v, replacement),
            Sum(es) => es.iter_mut().for_each(|e| e.replace_var(v, replacement)),
            Mul(es) => es.iter_mut().for_each(|e| e.replace_var(v, replacement)),
        }
    }
}

struct AnalysisResult {
    polys: Vec<ResolvedPoly>,
    lookups: Vec<ResolvedLookup>,
    var_bounds: Vec<(Cell, Bound)>,
    plaf: Plaf,
}

impl AnalysisResult {
    fn write_files(&self, name: &str) -> Result<(), io::Error> {
        if !Path::new("out").exists() {
            std::fs::create_dir("out")?;
            log::debug!("create out dir")
        }

        let mut base_file = File::create(format!("out/{}.toml", name))?;
        let mut fixed_file = File::create(format!("out/{}_fixed.csv", name))?;
        let mut polys_file = File::create(format!("out/{}_polys.toml", name))?;

        write!(base_file, "{}", PlafDisplayBaseTOML(&self.plaf))?;
        write!(fixed_file, "{}", PlafDisplayFixedCSV(&self.plaf))?;
        write!(polys_file, "{}", DisplayPolysBaseTOML::from(self))?;

        if !self.lookups.is_empty() {
            let mut lookups_file = File::create(format!("out/{}_lookups.toml", name))?;
            write!(lookups_file, "{}", DisplayLookupsBaseTOML::from(self))?;
        }

        Ok(())
    }
}

struct ResolvedPoly {
    name: String,
    expr: Expr<Cell>,
}

struct DisplayPolysBaseTOML<'a> {
    var_bounds: &'a Vec<(Cell, Bound)>,
    polys: &'a Vec<ResolvedPoly>,
    plaf: &'a Plaf,
}

impl<'a> From<&'a AnalysisResult> for DisplayPolysBaseTOML<'a> {
    fn from(value: &'a AnalysisResult) -> Self {
        DisplayPolysBaseTOML {
            var_bounds: &value.var_bounds,
            polys: &value.polys,
            plaf: &value.plaf,
        }
    }
}

impl fmt::Display for DisplayPolysBaseTOML<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cell_fmt = |f: &mut fmt::Formatter<'_>, c: &Cell| {
            write!(
                f,
                "{}",
                CellDisplay {
                    c,
                    plaf: &self.plaf
                }
            )
        };

        for (c, bound) in self.var_bounds {
            writeln!(
                f,
                "[constraints.resolved_polys.vars.\"{}\"]",
                CellDisplay {
                    c,
                    plaf: &self.plaf,
                }
            )?;
            writeln!(f, "bound = {}", bound)?;
        }
        writeln!(f)?;

        for p in self.polys {
            writeln!(f, "[constraints.resolved_polys.\"{}\"]", p.name)?;
            write!(f, "c = \"")?;
            write!(
                f,
                "{}",
                ExprDisplay {
                    e: &p.expr,
                    var_fmt: cell_fmt,
                }
            )?;
            writeln!(f, "\"")?;
        }

        Ok(())
    }
}

struct ResolvedLookup {
    name: String,
    exprs_num: (Vec<Expr<Cell>>, usize),
}

struct DisplayLookupsBaseTOML<'a> {
    lookups: &'a Vec<ResolvedLookup>,
    plaf: &'a Plaf,
}

impl<'a> From<&'a AnalysisResult> for DisplayLookupsBaseTOML<'a> {
    fn from(value: &'a AnalysisResult) -> Self {
        DisplayLookupsBaseTOML {
            lookups: &value.lookups,
            plaf: &value.plaf,
        }
    }
}

impl fmt::Display for DisplayLookupsBaseTOML<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cell_fmt = |f: &mut fmt::Formatter<'_>, c: &Cell| {
            write!(
                f,
                "{}",
                CellDisplay {
                    c,
                    plaf: &self.plaf
                }
            )
        };

        for l in self.lookups {
            writeln!(
                f,
                "[constraints.resolved_lookups.\"{}\"_\"{}\"]",
                l.exprs_num.1, l.name
            )?;
            write!(f, "l = [")?;
            for (i, exp) in l.exprs_num.0.iter().enumerate() {
                if i != 0 {
                    write!(f, ", ")?;
                }
                write!(
                    f,
                    "{}",
                    ExprDisplay {
                        e: &exp,
                        var_fmt: cell_fmt
                    },
                )?;
            }
            writeln!(f, "]")?;
        }

        Ok(())
    }
}
