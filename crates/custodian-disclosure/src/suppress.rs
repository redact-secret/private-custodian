//! Small-cell, complementary and composition-aware suppression (ADR 0061).
//!
//! The question this module answers: given everything an observer already
//! knows (the cells of past releases) and what this release would publish,
//! which cells must be withheld so that no withheld cell can be recovered, or
//! pinned into a narrow interval, by differencing?
//!
//! Model. For one metric, the strata are variables with a numerator and a
//! denominator. The policy declares linear relations `total = sum(parts)`
//! that hold for numerators and for denominators alike. A published cell makes
//! its variable *known*. An observer solves the relations for the unknown
//! variables. A cell is *exposed* if its value is determined by the relations
//! over the rationals, or if bounds derived from the relations (non-negativity
//! plus the known cells) squeeze it into an interval narrower than the
//! policy's `min_interval_width`.
//!
//! Algorithm.
//! 1. Primary suppression: a present cell whose denominator is below
//!    `min_stratum_size` is withheld.
//! 2. Gather what is known: this release's reported cells and every cell any
//!    earlier release in the series already published (numerators of the same
//!    measurement, denominators of the population). The relations are the
//!    union of this policy's and every earlier release's.
//! 3. Find exposed variables, separately for numerators and denominators.
//! 4. If none: done. Otherwise withhold one more cell: the first cell (in
//!    policy order) that shares a relation with an exposed variable, is
//!    present, is not yet withheld, and is not already public in the exposed
//!    family. Go to 3.
//! 5. If no such cell exists the release cannot be made safe: refuse
//!    ([`SuppressError::Unresolvable`]).
//!
//! The choice in step 4 uses only the structure and the policy order, never a
//! numerator of a withheld cell, so the pattern of withheld cells is a function
//! of public information plus the (public) fact that primary cells are small.
//!
//! Limits (docs/disclosure.md): the exact test is complete for linear
//! relations; the interval test is bound propagation, not linear programming,
//! so on cyclic overlapping structures it can overstate the uncertainty;
//! relations the policy does not declare are invisible to it; and it says
//! nothing about external knowledge, per-case outcomes inside a reported cell,
//! or the number of times a requester may ask (that is the budget).

use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuppressError {
    /// No further withholding makes the release safe.
    Unresolvable,
    /// A value in this release contradicts one already revealed, or the
    /// relations are contradictory.
    Conflict,
    /// Exact arithmetic would overflow; refused rather than approximated.
    Arithmetic,
}

/// One metric's problem. All vectors are indexed by variable (stratum).
#[derive(Clone, Debug)]
pub struct Problem {
    /// Whether the variable has a value in this release.
    pub present: Vec<bool>,
    pub num: Vec<u64>,
    pub den: Vec<u64>,
    /// `(total, parts)` over variable indices: the union of this policy's
    /// relations and those of earlier releases in the series.
    pub relations: Vec<(usize, Vec<usize>)>,
    /// Already public: numerator of the same measurement.
    pub prior_num: Vec<Option<u64>>,
    /// Already public: denominator for this population.
    pub prior_den: Vec<Option<u64>>,
    pub min_size: u64,
    pub min_width: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Num,
    Den,
}

/// Which present cells to withhold. The result has one flag per variable.
pub fn suppress(p: &Problem) -> Result<Vec<bool>, SuppressError> {
    let n = p.present.len();
    if p.num.len() != n || p.den.len() != n || p.prior_num.len() != n || p.prior_den.len() != n {
        return Err(SuppressError::Conflict);
    }
    for (t, parts) in &p.relations {
        if *t >= n || parts.iter().any(|x| *x >= n) {
            return Err(SuppressError::Conflict);
        }
    }
    for i in 0..n {
        if p.present[i] {
            if p.prior_num[i].is_some_and(|v| v != p.num[i])
                || p.prior_den[i].is_some_and(|v| v != p.den[i])
            {
                return Err(SuppressError::Conflict);
            }
            if p.num[i] > p.den[i] {
                return Err(SuppressError::Conflict);
            }
        }
    }
    let mut suppressed: Vec<bool> = (0..n)
        .map(|i| p.present[i] && p.den[i] < p.min_size)
        .collect();
    for _ in 0..=n {
        let known_num: Vec<Option<u64>> = (0..n)
            .map(|i| {
                if p.present[i] && !suppressed[i] {
                    Some(p.num[i])
                } else {
                    p.prior_num[i]
                }
            })
            .collect();
        let known_den: Vec<Option<u64>> = (0..n)
            .map(|i| {
                if p.present[i] && !suppressed[i] {
                    Some(p.den[i])
                } else {
                    p.prior_den[i]
                }
            })
            .collect();
        let en = exposed(n, &p.relations, &known_num, p.min_width)?;
        let ed = exposed(n, &p.relations, &known_den, p.min_width)?;
        if en.is_empty() && ed.is_empty() {
            return Ok(suppressed);
        }
        // Candidates for the first exposed variable, in policy order. Prefer
        // the first one whose withholding actually removes that exposure;
        // otherwise take the first (progress toward a larger withheld set).
        let mut picked = None;
        'search: for (fam, set) in [(Family::Num, &en), (Family::Den, &ed)] {
            let known = if fam == Family::Num {
                &known_num
            } else {
                &known_den
            };
            for &v in set {
                let mut candidates: Vec<usize> = Vec::new();
                for (t, parts) in &p.relations {
                    if *t != v && !parts.contains(&v) {
                        continue;
                    }
                    let mut members: Vec<usize> = parts.clone();
                    members.push(*t);
                    members.sort_unstable();
                    for c in members {
                        let public = match fam {
                            Family::Num => p.prior_num[c].is_some(),
                            Family::Den => p.prior_den[c].is_some(),
                        };
                        if c != v
                            && p.present[c]
                            && !suppressed[c]
                            && !public
                            && !candidates.contains(&c)
                        {
                            candidates.push(c);
                        }
                    }
                }
                let Some(first) = candidates.first().copied() else {
                    continue;
                };
                let mut choice = first;
                for c in &candidates {
                    let mut trial = known.clone();
                    trial[*c] = None;
                    let still = exposed(n, &p.relations, &trial, p.min_width)?;
                    if !still.contains(&v) {
                        choice = *c;
                        break;
                    }
                }
                picked = Some(choice);
                break 'search;
            }
        }
        match picked {
            Some(c) => suppressed[c] = true,
            None => return Err(SuppressError::Unresolvable),
        }
    }
    Err(SuppressError::Unresolvable)
}

// --- Exposure ----------------------------------------------------------------

/// Unknown variables an observer can pin down: exactly determined by the
/// relations, or bounded into an interval narrower than `min_width`.
pub fn exposed(
    n: usize,
    relations: &[(usize, Vec<usize>)],
    known: &[Option<u64>],
    min_width: u64,
) -> Result<BTreeSet<usize>, SuppressError> {
    let mut out = determined(n, relations, known)?;
    out.extend(narrow(n, relations, known, min_width)?);
    Ok(out)
}

// Exact rational arithmetic with overflow checks.

#[derive(Clone, Copy, PartialEq, Eq)]
struct Frac {
    n: i128,
    d: i128,
}

fn gcd(mut a: i128, mut b: i128) -> i128 {
    a = a.abs();
    b = b.abs();
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

impl Frac {
    const ZERO: Frac = Frac { n: 0, d: 1 };
    const ONE: Frac = Frac { n: 1, d: 1 };

    fn new(n: i128, d: i128) -> Option<Frac> {
        if d == 0 {
            return None;
        }
        let g = gcd(n, d).max(1);
        let (n, d) = (n / g, d / g);
        if d < 0 {
            Some(Frac {
                n: n.checked_neg()?,
                d: d.checked_neg()?,
            })
        } else {
            Some(Frac { n, d })
        }
    }

    fn is_zero(self) -> bool {
        self.n == 0
    }

    fn sub(self, o: Frac) -> Option<Frac> {
        Frac::new(
            self.n
                .checked_mul(o.d)?
                .checked_sub(o.n.checked_mul(self.d)?)?,
            self.d.checked_mul(o.d)?,
        )
    }

    fn mul(self, o: Frac) -> Option<Frac> {
        Frac::new(self.n.checked_mul(o.n)?, self.d.checked_mul(o.d)?)
    }

    fn inv(self) -> Option<Frac> {
        Frac::new(self.d, self.n)
    }
}

/// Variables whose value follows exactly from the relations and the known
/// cells (row-reduction over the unknown columns).
fn determined(
    n: usize,
    relations: &[(usize, Vec<usize>)],
    known: &[Option<u64>],
) -> Result<BTreeSet<usize>, SuppressError> {
    let cols: Vec<usize> = (0..n).filter(|i| known[*i].is_none()).collect();
    let mut col_of = vec![usize::MAX; n];
    for (c, v) in cols.iter().enumerate() {
        col_of[*v] = c;
    }
    let m = cols.len();
    let mut rows: Vec<Vec<Frac>> = Vec::new();
    for (t, parts) in relations {
        let mut row = vec![Frac::ZERO; m];
        let mut any = false;
        for p in parts {
            if known[*p].is_none() {
                row[col_of[*p]] = Frac::ONE;
                any = true;
            }
        }
        if known[*t].is_none() {
            row[col_of[*t]] = Frac::new(-1, 1).ok_or(SuppressError::Arithmetic)?;
            any = true;
        }
        if any {
            rows.push(row);
        }
    }
    let mut rank = 0;
    for c in 0..m {
        let Some(pivot) = (rank..rows.len()).find(|r| !rows[*r][c].is_zero()) else {
            continue;
        };
        rows.swap(rank, pivot);
        let inv = rows[rank][c].inv().ok_or(SuppressError::Arithmetic)?;
        for x in rows[rank].iter_mut() {
            *x = x.mul(inv).ok_or(SuppressError::Arithmetic)?;
        }
        let pivot_row = rows[rank].clone();
        for (r, row) in rows.iter_mut().enumerate() {
            if r == rank || row[c].is_zero() {
                continue;
            }
            let f = row[c];
            for (x, pv) in row.iter_mut().zip(&pivot_row) {
                let sub = f.mul(*pv).ok_or(SuppressError::Arithmetic)?;
                *x = x.sub(sub).ok_or(SuppressError::Arithmetic)?;
            }
        }
        rank += 1;
    }
    let mut out = BTreeSet::new();
    for row in rows.iter().take(rank) {
        let nz: Vec<usize> = (0..m).filter(|c| !row[*c].is_zero()).collect();
        if nz.len() == 1 {
            out.insert(cols[nz[0]]);
        }
    }
    Ok(out)
}

const INF: i128 = i128::MAX / 8;

/// Unknown variables whose propagated interval is narrower than `min_width`.
fn narrow(
    n: usize,
    relations: &[(usize, Vec<usize>)],
    known: &[Option<u64>],
    min_width: u64,
) -> Result<BTreeSet<usize>, SuppressError> {
    let mut lo = vec![0i128; n];
    let mut hi = vec![INF; n];
    for i in 0..n {
        if let Some(v) = known[i] {
            lo[i] = i128::from(v);
            hi[i] = i128::from(v);
        }
    }
    for _ in 0..(64 * n + 64) {
        let mut changed = false;
        for (t, parts) in relations {
            let sum_lo: i128 = parts.iter().map(|p| lo[*p]).sum();
            let sum_hi: i128 = if parts.iter().any(|p| hi[*p] >= INF) {
                INF
            } else {
                parts.iter().map(|p| hi[*p]).sum()
            };
            if sum_lo > lo[*t] {
                lo[*t] = sum_lo;
                changed = true;
            }
            if sum_hi < hi[*t] {
                hi[*t] = sum_hi;
                changed = true;
            }
            for k in parts {
                let others_lo = sum_lo - lo[*k];
                let others_hi_inf = parts.iter().any(|p| p != k && hi[*p] >= INF);
                if hi[*t] < INF {
                    let new_hi = hi[*t] - others_lo;
                    if new_hi < hi[*k] {
                        hi[*k] = new_hi;
                        changed = true;
                    }
                }
                if !others_hi_inf {
                    let others_hi: i128 = parts.iter().filter(|p| *p != k).map(|p| hi[*p]).sum();
                    let new_lo = lo[*t] - others_hi;
                    if new_lo > lo[*k] {
                        lo[*k] = new_lo;
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    let mut out = BTreeSet::new();
    for i in 0..n {
        if lo[i] > hi[i] {
            return Err(SuppressError::Conflict);
        }
        if known[i].is_none() && hi[i] < INF && hi[i] - lo[i] < i128::from(min_width) {
            out.insert(i);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problem(
        num: &[u64],
        den: &[u64],
        relations: Vec<(usize, Vec<usize>)>,
        min_size: u64,
        min_width: u64,
    ) -> Problem {
        let n = num.len();
        Problem {
            present: vec![true; n],
            num: num.to_vec(),
            den: den.to_vec(),
            relations,
            prior_num: vec![None; n],
            prior_den: vec![None; n],
            min_size,
            min_width,
        }
    }

    // Variables: 0 = x1, 1 = x2, 2 = x3 (small), 3 = all.
    fn x_table() -> Problem {
        problem(
            &[30, 18, 2, 50],
            &[40, 30, 5, 75],
            vec![(3, vec![0, 1, 2])],
            10,
            2,
        )
    }

    #[test]
    fn primary_cell_alone_would_be_differenced_so_a_second_cell_is_withheld() {
        let s = suppress(&x_table()).unwrap();
        assert_eq!(
            s,
            vec![true, false, true, false]
                .into_iter()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn no_small_cell_and_no_exposure_means_nothing_is_withheld() {
        let p = problem(
            &[30, 18, 20, 68],
            &[40, 30, 25, 95],
            vec![(3, vec![0, 1, 2])],
            10,
            2,
        );
        assert_eq!(suppress(&p).unwrap(), vec![false; 4]);
    }

    #[test]
    fn overlapping_total_is_covered_by_the_union_of_relations() {
        // Variables: 0 = x1, 1 = x2, 2 = x3 (small), 3 = y2, 4 = z, 5 = all.
        // all = x1 + x2 + x3 and y2 = x3 + z.
        let p = problem(
            &[30, 18, 2, 12, 10, 50],
            &[40, 30, 5, 15, 10, 75],
            vec![(5, vec![0, 1, 2]), (3, vec![2, 4])],
            10,
            2,
        );
        let s = suppress(&p).unwrap();
        // x3 is withheld; withholding only one more cell in one relation
        // would leave it determined through the other.
        assert!(s[2]);
        let known_num: Vec<Option<u64>> = (0..6)
            .map(|i| if s[i] { None } else { Some(p.num[i]) })
            .collect();
        assert!(!exposed(6, &p.relations, &known_num, 2)
            .unwrap()
            .contains(&2));
    }

    #[test]
    fn zero_total_would_pin_withheld_children_so_more_is_withheld() {
        // all = a + b + c with a, b small; all = 0 forces everything to 0.
        let p = problem(
            &[0, 0, 0, 0],
            &[3, 4, 50, 57],
            vec![(3, vec![0, 1, 2])],
            10,
            1,
        );
        let s = suppress(&p).unwrap();
        assert!(s[0] && s[1]);
        // c = all - a - b would be 0 by bounds unless c or all is withheld.
        assert!(s[2] || s[3]);
    }

    #[test]
    fn earlier_releases_count_as_known() {
        // Release 1 (already public): all = 50 and x1 = 30. This release
        // reports x2 = 18 and withholds x3: x3 = 50 - 30 - 18 is exposed
        // through the earlier release unless more is withheld.
        let mut p = x_table();
        p.prior_num = vec![Some(30), None, None, Some(50)];
        p.prior_den = vec![Some(40), None, None, Some(75)];
        let s = suppress(&p).unwrap();
        assert!(s[1] || s[2]);
        let known_num: Vec<Option<u64>> = (0..4)
            .map(|i| if s[i] { p.prior_num[i] } else { Some(p.num[i]) })
            .collect();
        assert!(!exposed(4, &p.relations, &known_num, 2)
            .unwrap()
            .contains(&2));
    }

    #[test]
    fn contradicting_an_earlier_release_is_a_conflict() {
        let mut p = x_table();
        p.prior_num = vec![Some(31), None, None, None];
        assert_eq!(suppress(&p), Err(SuppressError::Conflict));
    }

    #[test]
    fn nothing_left_to_withhold_is_unresolvable() {
        // Every other member of the only relation is already public.
        let mut p = problem(&[30, 2, 32], &[40, 5, 45], vec![(2, vec![0, 1])], 10, 1);
        p.prior_num = vec![Some(30), None, Some(32)];
        p.prior_den = vec![Some(40), None, Some(45)];
        assert_eq!(suppress(&p), Err(SuppressError::Unresolvable));
    }

    #[test]
    fn exact_solver_finds_a_three_way_cycle_that_single_unknown_solving_misses() {
        // a + b = P, a + c = Q, b + c = R with a, b, c unknown and P, Q, R
        // known: each of a, b, c is determined although no relation has a
        // single unknown.
        let relations = vec![(3, vec![0, 1]), (4, vec![0, 2]), (5, vec![1, 2])];
        let known = vec![None, None, None, Some(7), Some(5), Some(6)];
        let e = exposed(6, &relations, &known, 1).unwrap();
        assert_eq!(e, [0, 1, 2].into_iter().collect());
    }
}
