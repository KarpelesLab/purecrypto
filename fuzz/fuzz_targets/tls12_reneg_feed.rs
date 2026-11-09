//! Fuzz TLS 1.2 secure renegotiation (RFC 5746) — the post-handshake
//! ClientHello / HelloRequest handling and the second handshake that runs
//! under the first one's keys.
//!
//! The plain feed targets never get here: everything after the first
//! `Finished` is encrypted, and a fuzzer cannot produce a record that
//! authenticates. This target therefore completes a real handshake between
//! two in-process `Connection`s on every iteration and then sits between
//! them as a man in the middle *that holds the session keys*, which is the
//! threat model renegotiation actually has: the peer is authenticated and
//! is the one sending the hostile post-handshake messages.
//!
//! The keys come through public API only. Both configurations register a
//! `KeyLog` sink, which receives the master secret (`CLIENT_RANDOM` line);
//! the server random is read off the plaintext ServerHello; the suite is
//! pinned to `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`, whose record
//! protection (RFC 7905) is a dozen lines over `cipher::ChaCha20Poly1305`
//! and the TLS 1.2 PRF over `hash::Hmac`. With those the harness can open
//! any record either peer emits under the first epoch, rewrite it, and
//! seal it again with the sequence number the receiver expects — or seal
//! a record of its own.
//!
//! The input is a configuration byte followed by a script of operations:
//!
//! * start a renegotiation from either side (`Connection::renegotiate`);
//! * send application data from either side;
//! * forward the next record in either direction — as is, or with its
//!   content type replaced, bytes patched and / or its tail cut off (so a
//!   genuine renegotiation ClientHello, with its correct
//!   `renegotiation_info`, is one patch away from every malformed variant);
//! * inject a record with a fuzz-chosen content type and plaintext;
//! * drop a record; close either side.
//!
//! The configuration byte picks the renegotiation policy on each side
//! (off / on) and the server's client-initiated limit and limit action
//! (`Close`, `Refuse`, `Notify`).
//!
//! Records of the *second* epoch (after a renegotiation's
//! ChangeCipherSpec) are forwarded opaquely: following the key change
//! would need the new master secret matched to a direction, and the
//! handshake that matters here — the one driven by hostile messages —
//! runs entirely under the first epoch.
//!
//! Beyond "no panic", one property is asserted: in a direction the script
//! never tampered with, the receiver's application data is a prefix of
//! what the sender wrote. Renegotiation holds application data back and
//! swaps keys mid-stream; reordering, duplicating or dropping bytes across
//! that boundary is exactly the kind of bug this is here to find.
//!
//! All entropy comes from a DRBG reseeded at the start of every
//! iteration, so a crashing input replays to the same handshake and keys.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::cipher::ChaCha20Poly1305;
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::hash::{HmacSha256, Sha256};
use purecrypto::rng::{HmacDrbg, RngCore};
use purecrypto::tls::{
    Config, Connection, EntropySource, KeyLog, ProtocolVersion, RenegotiationLimit,
    RenegotiationLimitAction, RenegotiationPolicy, RootCertStore, SigningKey,
};
use purecrypto::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};

const HOST: &str = "fuzz.example";
const SUITE: u16 = 0xCCA9; // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
const MAX_INPUT: usize = 4096;
/// Each operation moves at most a flight; a renegotiation needs about ten.
const MAX_OPS: usize = 64;

const HANDSHAKE: u8 = 22;
const APPLICATION_DATA: u8 = 23;
const ALERT: u8 = 21;
const CHANGE_CIPHER_SPEC: u8 = 20;

// ---- deterministic entropy + key log -------------------------------------

struct FuzzRng(Mutex<HmacDrbg<Sha256>>);

impl FuzzRng {
    fn fresh() -> HmacDrbg<Sha256> {
        HmacDrbg::<Sha256>::new(b"tls12-reneg-feed-entropy-seed-00", b"nonce", &[])
    }
    fn reset(&self) {
        *self.0.lock().unwrap() = Self::fresh();
    }
}

impl EntropySource for FuzzRng {
    fn fill(&self, dest: &mut [u8]) {
        self.0.lock().unwrap().fill_bytes(dest);
    }
}

/// Collects `(client_random, master_secret)` from the `CLIENT_RANDOM`
/// lines.
#[derive(Default)]
struct Secrets(Mutex<Vec<([u8; 32], Vec<u8>)>>);

impl KeyLog for Secrets {
    fn log(&self, label: &str, client_random: &[u8; 32], secret: &[u8]) {
        if label == "CLIENT_RANDOM" {
            self.0
                .lock()
                .unwrap()
                .push((*client_random, secret.to_vec()));
        }
    }
}

// ---- configurations -------------------------------------------------------

struct Setup {
    rng: Arc<FuzzRng>,
    secrets: Arc<Secrets>,
    /// Indexed by "renegotiation enabled".
    clients: [Config; 2],
    /// Index 0: renegotiation off. 1..=4: on, with each limit variant.
    servers: [Config; 5],
}

static SETUP: OnceLock<Setup> = OnceLock::new();

fn setup() -> &'static Setup {
    SETUP.get_or_init(|| {
        let key = || {
            let mut rng = HmacDrbg::<Sha256>::new(b"tls12-reneg-feed-server-key", b"nonce", &[]);
            BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng)
        };
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key()),
            &DistinguishedName::common_name(HOST),
            &Validity::new(
                Time::utc(2024, 1, 1, 0, 0, 0),
                Time::utc(2099, 1, 1, 0, 0, 0),
            ),
            1,
            false,
            &[HOST],
        )
        .unwrap()
        .to_der()
        .to_vec();

        let rng = Arc::new(FuzzRng(Mutex::new(FuzzRng::fresh())));
        let secrets = Arc::new(Secrets::default());
        let v12 = ProtocolVersion::TLSv1_2;

        let client = |enabled: bool| {
            let mut roots = RootCertStore::new();
            roots.add_der(cert.clone()).unwrap();
            Config::builder()
                .tls_only()
                .rng(rng.clone())
                .key_log(secrets.clone())
                .versions(v12, v12)
                .cipher_suites(&[SUITE])
                .roots(roots)
                .server_name(HOST)
                .verification_time(Time::utc(2030, 6, 1, 0, 0, 0))
                .allow_renegotiation(enabled)
                .build()
        };
        let server = |policy: RenegotiationPolicy| {
            Config::builder()
                .tls_only()
                .rng(rng.clone())
                .key_log(secrets.clone())
                .versions(v12, v12)
                .cipher_suites(&[SUITE])
                .identity(vec![cert.clone()], SigningKey::Ecdsa(key()))
                .renegotiation(policy)
                .build()
        };
        let limited = |max: u32, action| {
            RenegotiationPolicy::enabled()
                .with_client_limit(Some(RenegotiationLimit {
                    max,
                    window_secs: 300,
                }))
                .with_limit_action(action)
        };
        let servers = [
            server(RenegotiationPolicy::disabled()),
            // The default limit (2 per 300 s, `Close`).
            server(RenegotiationPolicy::enabled()),
            server(limited(0, RenegotiationLimitAction::Close)),
            server(limited(1, RenegotiationLimitAction::Refuse)),
            server(limited(1, RenegotiationLimitAction::Notify)),
        ];
        let clients = [client(false), client(true)];
        Setup {
            rng,
            secrets,
            clients,
            servers,
        }
    })
}

// ---- TLS 1.2 record protection for the pinned suite -----------------------

/// TLS 1.2 PRF with SHA-256 (RFC 5246 §5).
fn prf(secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
    let label_seed = [label, seed].concat();
    let mut a = HmacSha256::mac(secret, &label_seed);
    for chunk in out.chunks_mut(32) {
        let block = HmacSha256::mac(secret, &[&a[..], &label_seed].concat());
        chunk.copy_from_slice(&block[..chunk.len()]);
        a = HmacSha256::mac(secret, &a);
    }
}

/// One direction's write key and IV.
struct RecordKey {
    aead: ChaCha20Poly1305,
    iv: [u8; 12],
}

impl RecordKey {
    fn nonce(&self, seq: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        for (n, s) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
            *n ^= s;
        }
        nonce
    }

    fn aad(seq: u64, content_type: u8, len: usize) -> [u8; 13] {
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        aad[8] = content_type;
        aad[9..11].copy_from_slice(&[3, 3]);
        aad[11..].copy_from_slice(&(len as u16).to_be_bytes());
        aad
    }

    /// A complete protected record.
    fn seal(&self, seq: u64, content_type: u8, plaintext: &[u8]) -> Vec<u8> {
        let mut body = plaintext.to_vec();
        let tag = self.aead.encrypt(
            &self.nonce(seq),
            &Self::aad(seq, content_type, body.len()),
            &mut body,
        );
        let mut record = vec![content_type, 3, 3];
        record.extend_from_slice(&((body.len() + 16) as u16).to_be_bytes());
        record.extend_from_slice(&body);
        record.extend_from_slice(&tag);
        record
    }

    /// The content type and plaintext of a complete protected record.
    fn open(&self, seq: u64, record: &[u8]) -> Option<(u8, Vec<u8>)> {
        let content_type = record[0];
        let body = &record[5..];
        let (ciphertext, tag) = body.split_at(body.len().checked_sub(16)?);
        let mut plaintext = ciphertext.to_vec();
        self.aead
            .decrypt(
                &self.nonce(seq),
                &Self::aad(seq, content_type, plaintext.len()),
                &mut plaintext,
                tag.try_into().unwrap(),
            )
            .ok()?;
        Some((content_type, plaintext))
    }
}

/// Derives both directions' keys: `[client write, server write]`.
fn record_keys(master: &[u8], client_random: &[u8], server_random: &[u8]) -> [RecordKey; 2] {
    // RFC 7905: no MAC keys; two 32-byte keys, then two 12-byte IVs.
    let mut block = [0u8; 88];
    prf(
        master,
        b"key expansion",
        &[server_random, client_random].concat(),
        &mut block,
    );
    let key = |at: usize| ChaCha20Poly1305::new(block[at..at + 32].try_into().unwrap());
    let iv = |at: usize| block[at..at + 12].try_into().unwrap();
    [
        RecordKey {
            aead: key(0),
            iv: iv(64),
        },
        RecordKey {
            aead: key(32),
            iv: iv(76),
        },
    ]
}

// ---- the two peers and the wire between them ------------------------------

struct Peer {
    conn: Connection,
    /// A fatal error came out of `feed`; nothing more is delivered.
    dead: bool,
    sent: Vec<u8>,
    received: Vec<u8>,
    /// Output bytes not yet forming a complete record.
    partial: Vec<u8>,
}

impl Peer {
    fn new(conn: Connection) -> Self {
        Peer {
            conn,
            dead: false,
            sent: Vec::new(),
            received: Vec::new(),
            partial: Vec::new(),
        }
    }

    fn deliver(&mut self, bytes: &[u8]) {
        if !self.dead && self.conn.feed(bytes).is_err() {
            self.dead = true;
        }
    }
}

/// A record on the wire: opened (first epoch) or left sealed (second).
enum Record {
    Clear(u8, Vec<u8>),
    Opaque(Vec<u8>),
}

/// One direction of the wire, as the man in the middle sees it.
struct Link {
    key: RecordKey,
    /// Records the sender produced, not yet forwarded.
    queue: VecDeque<Record>,
    /// The sequence number of the sender's next first-epoch record.
    sender_seq: u64,
    /// The sequence number the receiver expects next.
    receiver_seq: u64,
    /// The sender has moved to the second epoch: its records stay sealed.
    opaque: bool,
    /// The script changed, injected or dropped something in this direction.
    tampered: bool,
}

/// How a forwarded record is rewritten.
struct Rewrite {
    content_type: Option<u8>,
    patches: Vec<(u8, u8)>,
    truncate: Option<u8>,
}

impl Link {
    fn new(key: RecordKey) -> Self {
        Link {
            key,
            queue: VecDeque::new(),
            // `Finished` used sequence number 0 in each direction.
            sender_seq: 1,
            receiver_seq: 1,
            opaque: false,
            tampered: false,
        }
    }

    /// Takes a record off the sender, opening it while the sender is
    /// still in the first epoch.
    fn enqueue(&mut self, record: Vec<u8>) {
        if self.opaque {
            self.queue.push_back(Record::Opaque(record));
            return;
        }
        let (content_type, plaintext) = self
            .key
            .open(self.sender_seq, &record)
            .expect("harness lost sync with the first-epoch record keys");
        self.sender_seq += 1;
        // The renegotiation's ChangeCipherSpec: everything the sender
        // emits after it is under the new keys.
        if content_type == CHANGE_CIPHER_SPEC {
            self.opaque = true;
        }
        self.queue.push_back(Record::Clear(content_type, plaintext));
    }

    /// Forwards the next queued record to `to`, rewritten if asked.
    fn forward(&mut self, to: &mut Peer, rewrite: Option<Rewrite>) {
        let (mut content_type, mut plaintext) = match self.queue.pop_front() {
            None => return,
            Some(Record::Opaque(record)) => {
                to.deliver(&record);
                return;
            }
            Some(Record::Clear(content_type, plaintext)) => (content_type, plaintext),
        };
        if let Some(rw) = rewrite {
            self.tampered = true;
            if let Some(t) = rw.content_type {
                content_type = t;
            }
            for (pos, xor) in rw.patches {
                if !plaintext.is_empty() {
                    let len = plaintext.len();
                    plaintext[usize::from(pos) % len] ^= xor;
                }
            }
            if let Some(keep) = rw.truncate {
                plaintext.truncate(usize::from(keep) % (plaintext.len() + 1));
            }
        }
        self.inject(to, content_type, &plaintext);
    }

    /// Seals a first-epoch record with the receiver's next sequence number.
    fn inject(&mut self, to: &mut Peer, content_type: u8, plaintext: &[u8]) {
        let sealed = self.key.seal(self.receiver_seq, content_type, plaintext);
        self.receiver_seq += 1;
        to.deliver(&sealed);
    }
}

/// Moves everything `from` has produced into `link`'s queue, one record
/// per entry, and collects the application data it has received.
fn collect(from: &mut Peer, link: &mut Link) {
    while let Ok(bytes) = from.conn.pop() {
        if bytes.is_empty() {
            break;
        }
        from.partial.extend_from_slice(&bytes);
    }
    while from.partial.len() >= 5 {
        let len = 5 + usize::from(u16::from_be_bytes([from.partial[3], from.partial[4]]));
        if from.partial.len() < len {
            break;
        }
        link.enqueue(from.partial.drain(..len).collect());
    }
    while let Ok(data) = from.conn.recv() {
        if data.is_empty() {
            break;
        }
        from.received.extend_from_slice(&data);
    }
}

/// Runs the initial handshake and returns the peers with the wire keys.
fn connect(client_cfg: &Config, server_cfg: &Config) -> (Peer, Peer, [RecordKey; 2]) {
    let s = setup();
    s.rng.reset();
    s.secrets.0.lock().unwrap().clear();

    let mut client = Connection::client(client_cfg).expect("client connection");
    let mut server = Connection::server(server_cfg).expect("server connection");
    let mut server_random = None;
    for _ in 0..16 {
        let a = client.pop().expect("client flight");
        if !a.is_empty() {
            server.feed(&a).expect("server accepts the client flight");
        }
        let b = server.pop().expect("server flight");
        if !b.is_empty() {
            if server_random.is_none() {
                // record header (5) ‖ handshake header (4) ‖ version (2).
                assert_eq!((b[0], b[5]), (HANDSHAKE, 2), "expected a ServerHello");
                server_random = Some(b[11..43].to_vec());
            }
            client.feed(&b).expect("client accepts the server flight");
        }
        if a.is_empty() && b.is_empty() {
            break;
        }
    }
    assert!(client.is_handshake_complete() && server.is_handshake_complete());
    assert_eq!(client.negotiated_cipher_suite(), Some(SUITE));

    let (client_random, master) = s
        .secrets
        .0
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("the key log saw the master secret");
    let keys = record_keys(&master, &client_random, &server_random.unwrap());
    (Peer::new(client), Peer::new(server), keys)
}

// ---- the script -----------------------------------------------------------

/// Splits `n` bytes (or as many as remain) off the front of `data`.
fn take<'a>(data: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (head, tail) = data.split_at(n.min(data.len()));
    *data = tail;
    head
}

fn take_u8(data: &mut &[u8]) -> u8 {
    take(data, 1).first().copied().unwrap_or(0)
}

/// A content type from a selector byte: mostly the four real ones.
fn content_type(selector: u8) -> u8 {
    match selector {
        0..=0x7f => HANDSHAKE,
        0x80..=0xbf => APPLICATION_DATA,
        0xc0..=0xdf => ALERT,
        0xe0..=0xef => CHANGE_CIPHER_SPEC,
        other => other,
    }
}

fn take_rewrite(data: &mut &[u8]) -> Rewrite {
    let flags = take_u8(data);
    let content_type = (flags & 0x10 != 0).then(|| content_type(take_u8(data)));
    let patches = (0..flags & 3)
        .map(|_| (take_u8(data), take_u8(data)))
        .collect();
    let truncate = (flags & 0x20 != 0).then(|| take_u8(data));
    Rewrite {
        content_type,
        patches,
        truncate,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let Some((&cfg, mut script)) = data.split_first() else {
        return;
    };
    let s = setup();
    let client_cfg = &s.clients[usize::from(cfg & 1)];
    let server_cfg = &s.servers[if cfg & 2 == 0 {
        0
    } else {
        1 + usize::from((cfg >> 2) & 3)
    }];
    let (mut client, mut server, [client_key, server_key]) = connect(client_cfg, server_cfg);
    let mut c2s = Link::new(client_key);
    let mut s2c = Link::new(server_key);

    for _ in 0..MAX_OPS {
        if script.is_empty() {
            break;
        }
        let op = take_u8(&mut script);
        // The low bit picks the direction / the acting side.
        let (from, to, link) = if op & 1 == 0 {
            (&mut client, &mut server, &mut c2s)
        } else {
            (&mut server, &mut client, &mut s2c)
        };
        match (op >> 1) % 8 {
            0 => {
                let _ = from.conn.renegotiate();
            }
            1 => {
                let n = usize::from(take_u8(&mut script) % 48);
                let msg = take(&mut script, n);
                if from.conn.send(msg).is_ok() {
                    from.sent.extend_from_slice(msg);
                }
            }
            2 => link.forward(to, None),
            3 => {
                while !link.queue.is_empty() {
                    link.forward(to, None);
                }
            }
            4 => {
                let rewrite = take_rewrite(&mut script);
                link.forward(to, Some(rewrite));
            }
            5 => {
                let t = content_type(take_u8(&mut script));
                let n = usize::from(take_u8(&mut script));
                let plaintext = take(&mut script, n);
                link.tampered = true;
                link.inject(to, t, plaintext);
            }
            6 => {
                if link.queue.pop_front().is_some() {
                    link.tampered = true;
                }
            }
            _ => {
                let _ = from.conn.close();
            }
        }
        collect(&mut client, &mut c2s);
        collect(&mut server, &mut s2c);
    }

    // Let whatever is in flight land (a renegotiation the script started
    // but did not pump, held-back application data).
    for _ in 0..32 {
        if c2s.queue.is_empty() && s2c.queue.is_empty() {
            break;
        }
        while !c2s.queue.is_empty() {
            c2s.forward(&mut server, None);
        }
        while !s2c.queue.is_empty() {
            s2c.forward(&mut client, None);
        }
        collect(&mut client, &mut c2s);
        collect(&mut server, &mut s2c);
    }

    // Untampered directions deliver a prefix of what was written, in
    // order, whatever happened in the other direction.
    if !c2s.tampered {
        assert!(
            client.sent.starts_with(&server.received),
            "client-to-server application data was reordered, duplicated or forged"
        );
    }
    if !s2c.tampered {
        assert!(
            server.sent.starts_with(&client.received),
            "server-to-client application data was reordered, duplicated or forged"
        );
    }
});
