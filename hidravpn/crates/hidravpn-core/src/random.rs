//! Uniform choices from the operating system's randomness, for picking
//! nodes. Nothing here is logged.

use anyhow::{anyhow, Result};

/// A uniform index in `0..n`. Rejection sampling, so no value is favoured.
pub fn index(n: usize) -> Result<usize> {
    if n == 0 {
        return Err(anyhow!("nothing to choose from"));
    }
    let n64 = n as u64;
    let zone = u64::MAX - (u64::MAX % n64);
    loop {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).map_err(|e| anyhow!("no randomness available: {e}"))?;
        let r = u64::from_le_bytes(b);
        if r < zone {
            return Ok((r % n64) as usize);
        }
    }
}

/// A uniform index in `0..n` other than `not`, when there is one.
pub fn index_other_than(n: usize, not: usize) -> Result<Option<usize>> {
    if n <= 1 || not >= n {
        return Ok(if n == 0 { None } else { Some(0) }.filter(|&i| i != not));
    }
    let r = index(n - 1)?;
    Ok(Some(if r >= not { r + 1 } else { r }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_index_is_in_range_and_every_value_comes_up() {
        assert!(index(0).is_err());
        assert_eq!(index(1).unwrap(), 0);
        let mut seen = [false; 5];
        for _ in 0..500 {
            seen[index(5).unwrap()] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn another_index_is_never_the_current_one() {
        assert_eq!(index_other_than(0, 0).unwrap(), None);
        assert_eq!(index_other_than(1, 0).unwrap(), None);
        assert_eq!(index_other_than(2, 7).unwrap(), Some(0));
        let mut seen = [false; 4];
        for _ in 0..300 {
            let i = index_other_than(4, 2).unwrap().unwrap();
            assert_ne!(i, 2);
            seen[i] = true;
        }
        assert!(seen[0] && seen[1] && seen[3]);
    }
}
