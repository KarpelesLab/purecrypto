//! XMSS hash addresses (RFC 8391 §2.5).
//!
//! An address is eight 32-bit big-endian words (32 bytes). The first three
//! words — layer address, 64-bit tree address, and the `type` word — are shared
//! by all three address types (OTS Hash, L-tree, Hash Tree). The remaining four
//! words are type-specific; changing the `type` word zeroes them, per the RFC's
//! requirement that unused padding words stay zero.
//!
//! XMSS addressing differs from SLH-DSA's: there is no separate PRF address
//! type, the `keyAndMask` word takes values 0/1/2 to derive the hash key and
//! up to a 2n-byte bitmask, and the wire form is always the full 32 bytes.

/// Address `type` values (word 3 of an ADRS).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum AdrsType {
    /// OTS Hash Address (type 0): used for WOTS+ chains.
    Ots = 0,
    /// L-tree Address (type 1): compresses a WOTS+ public key to one node.
    Ltree = 1,
    /// Hash Tree Address (type 2): the Merkle tree (and hypertree subtrees).
    HashTree = 2,
}

/// An XMSS hash address: eight 32-bit words, serialized big-endian.
#[derive(Clone, Copy)]
pub(crate) struct Adrs {
    words: [u32; 8],
}

impl Adrs {
    /// A fresh, zeroed address.
    pub(crate) fn new() -> Self {
        Adrs { words: [0; 8] }
    }

    /// The 32-byte big-endian serialization (RFC 8391 §2.5).
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, w) in self.words.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    /// Word 0: layer address (XMSS^MT layer, 0 for the bottom subtree).
    pub(crate) fn set_layer(&mut self, layer: u32) {
        self.words[0] = layer;
    }

    /// Words 1–2: the 64-bit tree address within a layer.
    pub(crate) fn set_tree(&mut self, tree: u64) {
        self.words[1] = (tree >> 32) as u32;
        self.words[2] = tree as u32;
    }

    /// Word 3: the address type. Per the RFC, all following words are zeroed
    /// when the type changes to keep padding words zero.
    pub(crate) fn set_type(&mut self, ty: AdrsType) {
        self.words[3] = ty as u32;
        self.words[4] = 0;
        self.words[5] = 0;
        self.words[6] = 0;
        self.words[7] = 0;
    }

    /// Copies the layer/tree fields (words 0–2) from `src`.
    pub(crate) fn copy_subtree(&mut self, src: &Adrs) {
        self.words[0] = src.words[0];
        self.words[1] = src.words[1];
        self.words[2] = src.words[2];
    }

    // --- OTS Hash Address (type 0) fields ---

    /// Word 4 (OTS type): which WOTS+ key pair within the subtree.
    pub(crate) fn set_ots(&mut self, ots: u32) {
        self.words[4] = ots;
    }

    /// Word 5 (OTS type): which of the `len` WOTS+ chains.
    pub(crate) fn set_chain(&mut self, chain: u32) {
        self.words[5] = chain;
    }

    /// Word 6 (OTS type): position within a WOTS+ chain.
    pub(crate) fn set_hash(&mut self, hash: u32) {
        self.words[6] = hash;
    }

    // --- L-tree Address (type 1) field ---

    /// Word 4 (L-tree type): which leaf's L-tree.
    pub(crate) fn set_ltree(&mut self, ltree: u32) {
        self.words[4] = ltree;
    }

    // --- Hash Tree / L-tree shared fields (words 5–6) ---

    /// Word 5: tree height (the current Merkle/L-tree level).
    pub(crate) fn set_tree_height(&mut self, height: u32) {
        self.words[5] = height;
    }

    /// Word 6: tree index (node position within the level).
    pub(crate) fn set_tree_index(&mut self, index: u32) {
        self.words[6] = index;
    }

    /// Word 7: `keyAndMask` selector (0 = key, 1/2 = bitmask halves).
    pub(crate) fn set_key_and_mask(&mut self, k: u32) {
        self.words[7] = k;
    }
}
