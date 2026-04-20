use rand::TryRng;
use rand::rngs::SysRng;

pub fn generate_seed(n: usize) -> Vec<bool> {
    let mut rng = SysRng;
    (0..n)
        .map(|_| rng.try_next_u32().unwrap() & 1 == 1)
        .collect()
}
