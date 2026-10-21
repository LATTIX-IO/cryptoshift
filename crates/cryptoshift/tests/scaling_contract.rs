//! Deterministic scaling benchmark regression test.
#[path = "../benches/phase_scaling.rs"]
#[allow(dead_code)]
mod benchmark;

#[test]
fn bounded_scaling_profiles_replay() -> Result<(), Box<dyn std::error::Error>> {
    benchmark::run(true)
}
