//! SLH-DSA parameter sets at security category 1 (n = 16, SHA-256).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlhParams {
    pub name: &'static str,
    /// Hypertree height.
    pub h: usize,
    /// Hypertree layers.
    pub d: usize,
    /// Height of each XMSS tree, h' = h / d.
    pub hp: usize,
    /// FORS tree height.
    pub a: usize,
    /// FORS trees.
    pub k: usize,
    /// log2 of the Winternitz parameter.
    pub lg_w: usize,
    /// Message-digest length in bytes.
    pub m: usize,
}

/// SP 800-230 ipd (April 2026), Table 1: at most 2^24 signatures per key.
pub const SLH_DSA_SHA2_128_24: SlhParams = SlhParams {
    name: "SLH-DSA-SHA2-128-24",
    h: 22,
    d: 1,
    hp: 22,
    a: 24,
    k: 6,
    lg_w: 2,
    m: 21,
};

pub const N: usize = 16;

impl SlhParams {
    pub const fn w(&self) -> usize {
        1 << self.lg_w
    }

    /// FIPS 205 (5.1).
    pub const fn len1(&self) -> usize {
        (8 * N).div_ceil(self.lg_w)
    }

    /// FIPS 205 (5.2): floor(log2(len1 (w - 1)) / lg_w) + 1.
    pub const fn len2(&self) -> usize {
        let x = self.len1() * (self.w() - 1);
        let floor_log2 = (usize::BITS - 1 - x.leading_zeros()) as usize;
        floor_log2 / self.lg_w + 1
    }

    pub const fn len(&self) -> usize {
        self.len1() + self.len2()
    }

    /// Left shift applied to the checksum before it is encoded (Algorithm 7).
    pub const fn csum_shift(&self) -> usize {
        (8 - (self.len2() * self.lg_w) % 8) % 8
    }

    /// Bytes of the encoded checksum.
    pub const fn csum_bytes(&self) -> usize {
        (self.len2() * self.lg_w).div_ceil(8)
    }

    pub const fn md_bytes(&self) -> usize {
        (self.k * self.a).div_ceil(8)
    }

    pub const fn tree_bits(&self) -> usize {
        self.h - self.hp
    }

    pub const fn tree_bytes(&self) -> usize {
        self.tree_bits().div_ceil(8)
    }

    pub const fn leaf_bytes(&self) -> usize {
        self.hp.div_ceil(8)
    }

    pub const fn sig_bytes(&self) -> usize {
        N * (1 + self.k * (1 + self.a) + self.h + self.d * self.len())
    }

    pub const fn pk_bytes(&self) -> usize {
        2 * N
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_sizes_match_the_standards() {
        // SP 800-230 ipd Table 1.
        assert_eq!(SLH_DSA_SHA2_128_24.len1(), 64);
        assert_eq!(SLH_DSA_SHA2_128_24.len2(), 4);
        assert_eq!(SLH_DSA_SHA2_128_24.sig_bytes(), 3856);
        assert_eq!(
            SLH_DSA_SHA2_128_24.md_bytes()
                + SLH_DSA_SHA2_128_24.tree_bytes()
                + SLH_DSA_SHA2_128_24.leaf_bytes(),
            SLH_DSA_SHA2_128_24.m
        );
    }
}
