//! Hash addresses (FIPS 205 §4.2). Two wire formats share one implementation:
//! the 32-byte form (SHAKE) and the 22-byte compressed form (SHA-2).

/// Address types (the `type` word of an ADRS).
#[derive(Clone, Copy)]
#[repr(u32)]
pub(crate) enum AdrsType {
    WotsHash = 0,
    WotsPk = 1,
    Tree = 2,
    ForsTree = 3,
    ForsRoots = 4,
    WotsPrf = 5,
    ForsPrf = 6,
}

/// A hash address. `compressed` selects the 22-byte SHA-2 layout; otherwise the
/// 32-byte SHAKE layout is used.
#[derive(Clone, Copy)]
pub(crate) struct Adrs {
    buf: [u8; 32],
    compressed: bool,
}

impl Adrs {
    /// A fresh, zeroed address in the format required by `is_shake`.
    pub(crate) fn new(is_shake: bool) -> Self {
        Adrs {
            buf: [0; 32],
            compressed: !is_shake,
        }
    }

    fn len(&self) -> usize {
        if self.compressed { 22 } else { 32 }
    }

    /// The serialized address bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.buf[..self.len()]
    }

    pub(crate) fn set_layer(&mut self, l: u32) {
        if self.compressed {
            self.buf[0] = l as u8;
        } else {
            self.buf[0..4].copy_from_slice(&l.to_be_bytes());
        }
    }

    pub(crate) fn set_tree(&mut self, t: u64) {
        let off = if self.compressed { 1 } else { 8 };
        self.buf[off..off + 8].copy_from_slice(&t.to_be_bytes());
    }

    /// Sets the type word and clears everything after it.
    pub(crate) fn set_type_and_clear(&mut self, ty: AdrsType) {
        let off = if self.compressed { 9 } else { 19 };
        self.buf[off] = ty as u8;
        for b in self.buf[off + 1..].iter_mut() {
            *b = 0;
        }
    }

    fn off_keypair(&self) -> usize {
        if self.compressed { 10 } else { 20 }
    }
    fn off_chain(&self) -> usize {
        if self.compressed { 14 } else { 24 }
    }
    fn off_hash(&self) -> usize {
        if self.compressed { 18 } else { 28 }
    }

    pub(crate) fn set_key_pair(&mut self, i: u32) {
        let o = self.off_keypair();
        self.buf[o..o + 4].copy_from_slice(&i.to_be_bytes());
    }

    pub(crate) fn set_chain(&mut self, i: u32) {
        let o = self.off_chain();
        self.buf[o..o + 4].copy_from_slice(&i.to_be_bytes());
    }

    pub(crate) fn set_hash(&mut self, i: u32) {
        let o = self.off_hash();
        self.buf[o..o + 4].copy_from_slice(&i.to_be_bytes());
    }

    /// Tree height aliases the chain-address word.
    pub(crate) fn set_tree_height(&mut self, i: u32) {
        self.set_chain(i);
    }

    /// Tree index aliases the hash-address word.
    pub(crate) fn set_tree_index(&mut self, i: u32) {
        self.set_hash(i);
    }

    /// Copies the key-pair word from `src` (which must share the format).
    pub(crate) fn copy_key_pair(&mut self, src: &Adrs) {
        let o = self.off_keypair();
        self.buf[o..o + 4].copy_from_slice(&src.buf[o..o + 4]);
    }
}
