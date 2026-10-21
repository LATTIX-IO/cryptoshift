//! Deterministic scaling benchmark regression test.
#[path = "../benches/phase_scaling.rs"]
#[allow(dead_code)]
mod benchmark;

#[test]
fn bounded_scaling_profiles_replay() {
    benchmark::run(true).expect("synthetic scaling contract must replay");
}
