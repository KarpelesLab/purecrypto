//! RFC 5280 §6.1 certificate-policy-tree processing.
//!
//! This implements the `valid_policy_tree` state machine (RFC 5280 §6.1.2 –
//! §6.1.4) used to decide whether a validated certification path satisfies a
//! caller-supplied policy requirement. It is an **opt-in** layer: the default
//! TLS path runs with no policy constraint and never invokes this code, so
//! existing callers are unaffected. A caller that supplies an
//! `initial_policy_set` (and/or sets `initial_require_explicit_policy`) gets
//! the chain rejected when the computed policy tree cannot satisfy the
//! requirement.
//!
//! Inputs and conventions
//! ----------------------
//! The path is given leaf-first (`path[0]` is the end-entity, `path[last]` is
//! the topmost intermediate whose issuer is the trust anchor), matching the
//! shape used by [`super::verify`]. The algorithm itself, however, processes
//! certificates from the trust anchor downward, so internally we iterate the
//! slice in reverse. Each certificate is "certificate i" in RFC terms, with
//! i running 1..=n from the first cert below the anchor to the leaf.
//!
//! Scope / simplifications relative to the full RFC algorithm:
//!   * Policy qualifiers are not surfaced (the parser discards them); the tree
//!     carries policy OIDs and their expected-policy sets, which is all that
//!     the "is the tree non-empty for the required policies" decision needs.
//!   * `anyPolicy` qualifiers and the special qualifier-propagation rules are
//!     therefore not modeled, but the structural `anyPolicy` handling
//!     (inhibit-any-policy, expansion against the parent's expected set) is.

use crate::tls::Error;
use crate::x509::{Certificate, oid};
use alloc::vec::Vec;

/// An OID, as the arc vector the x509 layer produces.
type Oid = Vec<u64>;

/// Caller-supplied initial conditions for policy processing (RFC 5280 §6.1.1
/// inputs). Construct via [`PolicyOptions::require`]; the default
/// [`PolicyOptions::none`] disables policy processing entirely.
#[derive(Clone, Debug, Default)]
pub struct PolicyOptions {
    /// The `user-initial-policy-set`. `None` means the special value
    /// `any-policy` (no restriction on acceptable policies). `Some(set)`
    /// restricts the acceptable policies to `set`; an empty `set` means the
    /// caller will accept no policy, which (with explicit policy required)
    /// rejects every chain.
    pub initial_policies: Option<Vec<Oid>>,
    /// `initial-explicit-policy`: when true, the path is required to be valid
    /// for at least one of `initial_policies` — i.e. the policy tree must be
    /// non-empty at the end. This is what makes policy processing
    /// *enforcing*.
    pub require_explicit_policy: bool,
    /// `initial-policy-mapping-inhibit`: when true, policy mapping is
    /// inhibited from the start of the path.
    pub inhibit_policy_mapping: bool,
    /// `initial-any-policy-inhibit`: when true, `anyPolicy` is inhibited from
    /// the start of the path.
    pub inhibit_any_policy: bool,
}

impl PolicyOptions {
    /// No policy processing — the default. With this, policy-tree processing
    /// is a no-op and every chain that the rest of validation accepts is
    /// accepted.
    pub fn none() -> Self {
        PolicyOptions::default()
    }

    /// Require the path to be valid for at least one policy in `policies`
    /// (`initial-explicit-policy = true`, `user-initial-policy-set =
    /// policies`). An empty `policies` slice means "any policy is acceptable"
    /// is NOT in force — it requires a policy yet accepts none, so every chain
    /// is rejected; pass at least one OID (or `any_policy`) for a useful
    /// constraint.
    pub fn require(policies: &[&[u64]]) -> Self {
        PolicyOptions {
            initial_policies: Some(policies.iter().map(|p| p.to_vec()).collect()),
            require_explicit_policy: true,
            inhibit_policy_mapping: false,
            inhibit_any_policy: false,
        }
    }

    /// Whether policy processing is enabled at all. When neither an explicit
    /// policy is required nor a policy set is constrained, the result of the
    /// algorithm cannot reject a chain, so the caller can skip it.
    pub(crate) fn policy_processing_enabled(&self) -> bool {
        self.require_explicit_policy || self.initial_policies.is_some()
    }
}

/// A node in the `valid_policy_tree` (RFC 5280 §6.1.2). Nodes are stored in a
/// flat arena indexed by `usize`; `parent` links to the node's parent (the
/// root nodes created at depth 0 have `parent == usize::MAX`).
#[derive(Clone, Debug)]
struct Node {
    /// `valid_policy`: the policy OID this node asserts.
    valid_policy: Oid,
    /// `expected_policy_set`: the set of policy OIDs that, in the next
    /// certificate, are considered equivalent to `valid_policy` (RFC 5280
    /// §6.1.2(a)).
    expected_policy_set: Vec<Oid>,
    /// Index of the parent node, or `usize::MAX` for a depth-0 root.
    parent: usize,
    /// Depth in the tree (number of certificates processed when this node was
    /// created). The root nodes are depth 0.
    depth: usize,
}

/// The policy tree: an arena of [`Node`]s. `depth` tracks how many
/// certificates have been processed (the current leaf row of the tree).
struct PolicyTree {
    nodes: Vec<Node>,
    depth: usize,
}

impl PolicyTree {
    /// The initial tree (RFC 5280 §6.1.2): a single root node with
    /// `valid_policy = anyPolicy` and `expected_policy_set = { anyPolicy }`.
    fn initial() -> Self {
        PolicyTree {
            nodes: alloc::vec![Node {
                valid_policy: oid::ANY_POLICY.to_vec(),
                expected_policy_set: alloc::vec![oid::ANY_POLICY.to_vec()],
                parent: usize::MAX,
                depth: 0,
            }],
            depth: 0,
        }
    }

    /// Indices of nodes at the current deepest depth (the "leaves" of the tree
    /// against which the next certificate's policies are matched).
    fn leaf_indices(&self) -> Vec<usize> {
        let d = self.depth;
        (0..self.nodes.len())
            .filter(|&i| self.nodes[i].depth == d)
            .collect()
    }

    /// RFC 5280 §6.1.3(d): prune the tree of any node that has no child once a
    /// certificate row has been processed. Walk from the deepest row upward,
    /// deleting parents whose entire subtree has been removed. We model
    /// deletion by retaining only nodes that are on a path to a current-depth
    /// leaf.
    fn prune(&mut self) {
        // Mark every node reachable upward from a current-depth node.
        let mut keep = alloc::vec![false; self.nodes.len()];
        for i in 0..self.nodes.len() {
            if self.nodes[i].depth == self.depth {
                let mut cur = i;
                while cur != usize::MAX && !keep[cur] {
                    keep[cur] = true;
                    cur = self.nodes[cur].parent;
                }
            }
        }
        // Compact, rebuilding parent indices.
        let mut remap = alloc::vec![usize::MAX; self.nodes.len()];
        let mut new_nodes = Vec::new();
        for (old, node) in self.nodes.iter().enumerate() {
            if keep[old] {
                remap[old] = new_nodes.len();
                new_nodes.push(node.clone());
            }
        }
        for node in &mut new_nodes {
            if node.parent != usize::MAX {
                node.parent = remap[node.parent];
            }
        }
        self.nodes = new_nodes;
    }
}

/// Runs RFC 5280 §6.1 policy processing over `path` (leaf-first) anchored at a
/// trust anchor whose own constraints are taken as unconstrained (the anchor
/// is treated as asserting `anyPolicy`, the standard convention). Returns
/// `Ok(())` if the path satisfies `opts`, or [`Error::BadCertificate`] if an
/// explicit policy is required and the resulting authorities-constrained
/// policy set is empty, or if a certificate carries a critical
/// policy-related extension that cannot be satisfied.
///
/// When `opts` does not enable policy processing the function returns `Ok(())`
/// immediately, guaranteeing the default validation path is byte-for-byte
/// unchanged.
pub(crate) fn check_policies(path: &[Certificate], opts: &PolicyOptions) -> Result<(), Error> {
    if !opts.policy_processing_enabled() {
        return Ok(());
    }
    let n = path.len();
    if n == 0 {
        // An explicit policy was required but there is no certificate to carry
        // one: fail closed.
        return Err(Error::BadCertificate);
    }

    let mut tree = PolicyTree::initial();

    // State variables (RFC 5280 §6.1.2). Counters are capped at n + 1 to mean
    // "not yet decremented to 0"; we use saturating arithmetic and the
    // standard "set to value, decrement per non-self-issued cert" model.
    let mut explicit_policy: usize = if opts.require_explicit_policy {
        0
    } else {
        n + 1
    };
    let mut inhibit_any_policy: usize = if opts.inhibit_any_policy { 0 } else { n + 1 };
    let mut policy_mapping: usize = if opts.inhibit_policy_mapping {
        0
    } else {
        n + 1
    };

    // Process each certificate from the one just below the anchor (path[n-1])
    // down to the leaf (path[0]). `cert_index` is the RFC's i (1..=n).
    for cert_index in 1..=n {
        let cert = &path[n - cert_index];
        let is_final = cert_index == n;

        // --- §6.1.3 basic certificate processing (policy parts only) ---

        // (d): decrement counters BEFORE processing the policies of this cert
        // is NOT what the RFC says — the decrements happen in §6.1.4 (prepare
        // for next cert) for all but the final certificate, and the
        // explicit_policy "wrap-up" check is §6.1.5. We follow that ordering:
        // process policies here, then do §6.1.4 / §6.1.5 below.

        process_certificate_policies(&mut tree, cert, inhibit_any_policy)?;

        // (e): if certificatePolicies is absent, the entire tree is set to
        // NULL (empty). RFC 5280 §6.1.3(e).
        let policies = cert
            .certificate_policies()
            .map_err(|_| Error::BadCertificate)?;
        if policies.is_none() {
            tree.nodes.clear();
        } else {
            // (f) pruning handled inside process_certificate_policies via the
            // depth bump; prune dead branches now.
            tree.prune();
        }

        // (f): the explicit_policy check — if explicit_policy == 0 and the
        // tree is empty, this is a failure. Deferred to the wrap-up so that a
        // later mapping can't be the cause; per RFC the check is in §6.1.5 for
        // the final cert and the counters gate intermediate behavior.

        if !is_final {
            // --- §6.1.4 preparation for the next certificate ---
            prepare_for_next(
                &mut tree,
                cert,
                &mut explicit_policy,
                &mut policy_mapping,
                &mut inhibit_any_policy,
            )?;
        }
    }

    // --- §6.1.5 wrap-up procedure ---
    // (a)/(b): decrement/handle explicit_policy for the final certificate.
    // policyConstraints with requireExplicitPolicy == 0 on the final cert sets
    // explicit_policy to 0.
    if let Some((require, _inhibit, _crit)) = path[0]
        .policy_constraints()
        .map_err(|_| Error::BadCertificate)?
        && let Some(r) = require
        && (r as usize) == 0
    {
        explicit_policy = 0;
    }

    // (g): compute the intersection of the valid_policy_tree with the
    // user-initial-policy-set. We model "authorities-constrained-policy-set"
    // implicitly: the tree is non-empty iff some acceptable policy survives.
    let acceptable = intersect_with_user_set(&tree, opts.initial_policies.as_deref());

    // The path is policy-valid unless an explicit policy is required and there
    // is no acceptable policy.
    if explicit_policy == 0 && acceptable.is_empty() {
        return Err(Error::BadCertificate);
    }

    Ok(())
}

/// RFC 5280 §6.1.3(d): process this certificate's `certificatePolicies`
/// against the current tree, growing it one row deeper.
fn process_certificate_policies(
    tree: &mut PolicyTree,
    cert: &Certificate,
    inhibit_any_policy: usize,
) -> Result<(), Error> {
    let policies = cert
        .certificate_policies()
        .map_err(|_| Error::BadCertificate)?;
    let Some((policy_oids, _critical)) = policies else {
        // Absent certificatePolicies: handled by the caller (tree set to NULL).
        return Ok(());
    };

    let parent_leaves = tree.leaf_indices();
    let parent_depth = tree.depth;
    let new_depth = parent_depth + 1;

    // Separate anyPolicy from the concrete policies of this cert.
    let has_any = policy_oids.iter().any(|p| p.as_slice() == oid::ANY_POLICY);
    let concrete: Vec<&Oid> = policy_oids
        .iter()
        .filter(|p| p.as_slice() != oid::ANY_POLICY)
        .collect();

    let mut new_nodes: Vec<Node> = Vec::new();

    // (d)(1): for each policy P (not anyPolicy) in certificatePolicies:
    for p in &concrete {
        // (d)(1)(i): find parent leaf nodes whose expected_policy_set
        // contains P; create a child of each.
        let mut matched = false;
        for &pi in &parent_leaves {
            if tree.nodes[pi]
                .expected_policy_set
                .iter()
                .any(|e| e.as_slice() == p.as_slice())
            {
                matched = true;
                new_nodes.push(Node {
                    valid_policy: (*p).clone(),
                    expected_policy_set: alloc::vec![(*p).clone()],
                    parent: pi,
                    depth: new_depth,
                });
            }
        }
        // (d)(1)(ii): if no node matched and a parent leaf has
        // valid_policy == anyPolicy, create a child of that anyPolicy node.
        if !matched {
            for &pi in &parent_leaves {
                if tree.nodes[pi].valid_policy.as_slice() == oid::ANY_POLICY {
                    new_nodes.push(Node {
                        valid_policy: (*p).clone(),
                        expected_policy_set: alloc::vec![(*p).clone()],
                        parent: pi,
                        depth: new_depth,
                    });
                }
            }
        }
    }

    // (d)(2): if anyPolicy is present in certificatePolicies and
    // (inhibit_any_policy > 0 or (this is a CA and ...)), propagate the
    // parents' expected sets. We model the common case: when anyPolicy is
    // asserted and not inhibited, for each parent leaf node create a child for
    // every policy in the parent's expected_policy_set that does not already
    // have a child, plus carry an anyPolicy child of any anyPolicy parent.
    if has_any && inhibit_any_policy > 0 {
        for &pi in &parent_leaves {
            for e in tree.nodes[pi].expected_policy_set.clone() {
                let already = new_nodes
                    .iter()
                    .any(|nn| nn.parent == pi && nn.valid_policy == e);
                if !already {
                    new_nodes.push(Node {
                        valid_policy: e.clone(),
                        expected_policy_set: alloc::vec![e.clone()],
                        parent: pi,
                        depth: new_depth,
                    });
                }
            }
        }
    }

    // Commit the new row and advance depth.
    for node in new_nodes {
        tree.nodes.push(node);
    }
    tree.depth = new_depth;
    Ok(())
}

/// RFC 5280 §6.1.4 — prepare the state for the next certificate: process
/// `policyMappings`, decrement the counters for a non-self-issued certificate,
/// and apply this certificate's `policyConstraints` / `inhibitAnyPolicy`.
fn prepare_for_next(
    tree: &mut PolicyTree,
    cert: &Certificate,
    explicit_policy: &mut usize,
    policy_mapping: &mut usize,
    inhibit_any_policy: &mut usize,
) -> Result<(), Error> {
    // (b): policy mapping.
    if let Some((mappings, _crit)) = cert.policy_mappings().map_err(|_| Error::BadCertificate)? {
        if *policy_mapping > 0 {
            apply_policy_mappings(tree, &mappings);
        } else {
            // Mapping is inhibited: RFC 5280 §6.1.4(b)(2) — delete each node
            // of depth i whose valid_policy is an issuerDomainPolicy that is
            // mapped. We prune such nodes from the current leaf row.
            let d = tree.depth;
            let mapped: Vec<&Oid> = mappings.iter().map(|(i, _)| i).collect();
            let mut survive = Vec::new();
            for node in tree.nodes.drain(..) {
                let drop = node.depth == d
                    && mapped
                        .iter()
                        .any(|m| m.as_slice() == node.valid_policy.as_slice());
                if !drop {
                    survive.push(node);
                }
            }
            tree.nodes = survive;
            tree.prune();
        }
    }

    // (h)/(i)/(j): decrement counters (treating every cert as non-self-issued;
    // self-issued detection — issuer == subject with same key — would only
    // skip the decrement, a strict-but-safe simplification that can only make
    // the constraint fire SOONER, i.e. fail-closed).
    *explicit_policy = explicit_policy.saturating_sub(1);
    *policy_mapping = policy_mapping.saturating_sub(1);
    *inhibit_any_policy = inhibit_any_policy.saturating_sub(1);

    // (i): policyConstraints sets the counters to the smaller of the current
    // value and the field value.
    if let Some((require, inhibit, _crit)) = cert
        .policy_constraints()
        .map_err(|_| Error::BadCertificate)?
    {
        if let Some(r) = require {
            *explicit_policy = (*explicit_policy).min(r as usize);
        }
        if let Some(im) = inhibit {
            *policy_mapping = (*policy_mapping).min(im as usize);
        }
    }

    // (j): inhibitAnyPolicy.
    if let Some((skip, _crit)) = cert
        .inhibit_any_policy()
        .map_err(|_| Error::BadCertificate)?
    {
        *inhibit_any_policy = (*inhibit_any_policy).min(skip as usize);
    }

    Ok(())
}

/// RFC 5280 §6.1.4(b)(1): apply policy mappings to the current leaf row. For
/// each leaf node whose valid_policy is an issuerDomainPolicy `idp`, set its
/// expected_policy_set to the set of subjectDomainPolicies that `idp` maps to.
fn apply_policy_mappings(tree: &mut PolicyTree, mappings: &[(Oid, Oid)]) {
    let d = tree.depth;
    for i in 0..tree.nodes.len() {
        if tree.nodes[i].depth != d {
            continue;
        }
        let vp = tree.nodes[i].valid_policy.clone();
        let subjects: Vec<Oid> = mappings
            .iter()
            .filter(|(idp, _)| idp.as_slice() == vp.as_slice())
            .map(|(_, sdp)| sdp.clone())
            .collect();
        if !subjects.is_empty() {
            tree.nodes[i].expected_policy_set = subjects;
        }
    }
}

/// RFC 5280 §6.1.5(g) intersection: returns the set of policy OIDs the path is
/// valid for that are acceptable under `user_set`. `None` means
/// user-initial-policy-set is `any-policy` (accept every policy the path is
/// valid for).
///
/// The set of policies the path is valid for, expressed in the
/// trust-anchor/user domain, is carried by the **depth-1** nodes — the
/// policies asserted by the certificate just below the anchor, before any
/// policy mapping rewrote their `expected_policy_set` further down. Because
/// dead branches are pruned after each certificate, every surviving depth-1
/// node has a descendant in the leaf row, so its `valid_policy` is genuinely
/// valid for the whole path. (Using the leaf-row `valid_policy` instead would
/// report subject-domain policies and break policy-mapping translation.)
fn intersect_with_user_set(tree: &PolicyTree, user_set: Option<&[Oid]>) -> Vec<Oid> {
    // When the path has only the root row (no certificate asserted any policy
    // — i.e. depth 0), there are no valid policies. Otherwise the
    // domain-level policies live at depth 1.
    let domain_depth = if tree.depth >= 1 { 1 } else { tree.depth };
    let domain_indices: Vec<usize> = (0..tree.nodes.len())
        .filter(|&i| tree.nodes[i].depth == domain_depth)
        .collect();
    // anyPolicy may survive at depth 1 (e.g. a single anyPolicy-asserting cert
    // not yet constrained); treat it as the wildcard.
    let any_present = domain_indices
        .iter()
        .any(|&i| tree.nodes[i].valid_policy.as_slice() == oid::ANY_POLICY);
    let mut effective: Vec<Oid> = domain_indices
        .iter()
        .map(|&i| tree.nodes[i].valid_policy.clone())
        .filter(|p| p.as_slice() != oid::ANY_POLICY)
        .collect();

    match user_set {
        // user-initial-policy-set == any-policy: every effective policy is
        // acceptable. If the only thing left is anyPolicy, the tree is still
        // "valid for any policy", so report a non-empty result.
        None => {
            if any_present && effective.is_empty() {
                effective.push(oid::ANY_POLICY.to_vec());
            }
            effective
        }
        Some(set) => {
            let mut acceptable: Vec<Oid> = effective
                .iter()
                .filter(|p| set.iter().any(|u| u.as_slice() == p.as_slice()))
                .cloned()
                .collect();
            // If anyPolicy survived in the tree, the path places no
            // restriction, so every policy the user asked for is acceptable.
            if any_present {
                for u in set {
                    if !acceptable.iter().any(|p| p.as_slice() == u.as_slice()) {
                        acceptable.push(u.clone());
                    }
                }
            }
            acceptable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::BoxedRsaPrivateKey;
    use crate::signature_registry::SignaturePolicy;
    use crate::test_util::{rsa_test_key_a, rsa_test_key_b};
    use crate::tls::pki::store::RootCertStore;
    use crate::tls::pki::verify::{ChainPurpose, verify_chain_with_policy};
    use crate::x509::extension;
    use crate::x509::{CertSigner, Certificate, DistinguishedName, Extension, Time, Validity};
    use alloc::vec;
    use alloc::vec::Vec;

    // Two example policy OIDs and the CA/B-forum DV policy.
    const POLICY_A: &[u64] = &[2, 23, 140, 1, 2, 1]; // domain-validated
    const POLICY_B: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1];
    const POLICY_C: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 2];

    fn validity() -> Validity {
        Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        )
    }

    fn boxed(k: &crate::rsa::RsaPrivateKey<32>) -> BoxedRsaPrivateKey {
        BoxedRsaPrivateKey::from_pkcs1_der(&k.to_pkcs1_der()).unwrap()
    }

    /// Builds a 2-cert chain `[leaf, intermediate]` + a trust anchor, with the
    /// given extension lists on the intermediate and the leaf. Returns
    /// `(store, chain_der)`.
    fn build_chain(
        int_exts: &[Extension],
        leaf_exts: &[Extension],
    ) -> (RootCertStore, Vec<Vec<u8>>) {
        let root_k = rsa_test_key_a();
        let int_k = rsa_test_key_b();
        let leaf_k = rsa_test_key_b();
        let root_b = boxed(&root_k);
        let int_b = boxed(&int_k);

        let root_name = DistinguishedName::common_name("Policy Root");
        let int_name = DistinguishedName::common_name("Policy Intermediate");
        let leaf_name = DistinguishedName::common_name("leaf.example");

        // Root (anchor).
        let root = Certificate::self_signed(&root_k, &root_name, &validity(), 1, true).unwrap();

        // Intermediate: CA, signed by root.
        let mut int_all = vec![extension::basic_constraints(true, None)];
        int_all.extend_from_slice(int_exts);
        let intermediate = Certificate::issue_with_extensions(
            &CertSigner::Rsa(&root_b),
            &root_name,
            &int_name,
            &crate::x509::AnyPublicKey::Rsa(int_b.public_key()),
            &validity(),
            2,
            &int_all,
        )
        .unwrap();

        // Leaf: signed by intermediate.
        let mut leaf_all = vec![
            extension::basic_constraints(false, None),
            extension::subject_alt_name(&[crate::x509::GeneralName::Dns("leaf.example".into())]),
        ];
        leaf_all.extend_from_slice(leaf_exts);
        let leaf = Certificate::issue_with_extensions(
            &CertSigner::Rsa(&int_b),
            &int_name,
            &leaf_name,
            &crate::x509::AnyPublicKey::Rsa(boxed(&leaf_k).public_key()),
            &validity(),
            3,
            &leaf_all,
        )
        .unwrap();

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let chain = vec![leaf.to_der().to_vec(), intermediate.to_der().to_vec()];
        (store, chain)
    }

    fn verify(
        store: &RootCertStore,
        chain: &[Vec<u8>],
        opts: &PolicyOptions,
    ) -> Result<(), crate::tls::Error> {
        let empty = crate::tls::pki::CrlStore::new();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        verify_chain_with_policy(
            store,
            &empty,
            chain,
            Some(&now),
            &SignaturePolicy::modern(),
            ChainPurpose::Server,
            opts,
        )
        .map(|_| ())
    }

    #[test]
    fn default_options_are_noop() {
        // No certificatePolicies anywhere; with policy processing disabled the
        // chain validates (default behavior preserved).
        let (store, chain) = build_chain(&[], &[]);
        verify(&store, &chain, &PolicyOptions::none()).unwrap();
    }

    #[test]
    fn matching_required_policy_passes() {
        // Both intermediate and leaf assert POLICY_A; requiring POLICY_A
        // succeeds.
        let (store, chain) = build_chain(
            &[extension::certificate_policies(&[POLICY_A])],
            &[extension::certificate_policies(&[POLICY_A])],
        );
        verify(&store, &chain, &PolicyOptions::require(&[POLICY_A])).unwrap();
    }

    #[test]
    fn leaf_missing_required_policy_is_rejected() {
        // requireExplicitPolicy is set (via PolicyOptions::require) and the
        // leaf lacks the required policy → empty tree → reject.
        let (store, chain) = build_chain(
            &[extension::certificate_policies(&[POLICY_A])],
            &[extension::certificate_policies(&[POLICY_B])],
        );
        assert!(verify(&store, &chain, &PolicyOptions::require(&[POLICY_A])).is_err());
    }

    #[test]
    fn absent_policies_with_explicit_required_is_rejected() {
        // No certificatePolicies at all → tree becomes NULL at the first cert
        // → with explicit policy required, reject.
        let (store, chain) = build_chain(&[], &[]);
        assert!(verify(&store, &chain, &PolicyOptions::require(&[POLICY_A])).is_err());
    }

    #[test]
    fn any_policy_in_chain_satisfies_required_policy() {
        // Intermediate asserts anyPolicy, leaf asserts POLICY_A. Requiring
        // POLICY_A succeeds (anyPolicy expands to cover it).
        let (store, chain) = build_chain(
            &[extension::certificate_policies(&[oid::ANY_POLICY])],
            &[extension::certificate_policies(&[POLICY_A])],
        );
        verify(&store, &chain, &PolicyOptions::require(&[POLICY_A])).unwrap();
    }

    #[test]
    fn inhibit_any_policy_blocks_any_policy_expansion() {
        // initial-any-policy-inhibit = true: anyPolicy is inhibited from the
        // start of the path. The intermediate asserts ONLY anyPolicy, so with
        // anyPolicy inhibited it creates no anyPolicy node; the leaf's
        // concrete POLICY_A then has no parent to attach to → empty tree →
        // reject.
        let int_exts = [extension::certificate_policies(&[oid::ANY_POLICY])];
        let leaf_exts = [extension::certificate_policies(&[POLICY_A])];
        let (store, chain) = build_chain(&int_exts, &leaf_exts);
        let mut opts = PolicyOptions::require(&[POLICY_A]);
        opts.inhibit_any_policy = true;
        assert!(verify(&store, &chain, &opts).is_err());
        // Sanity: WITHOUT inhibiting anyPolicy the same shape passes (the
        // intermediate's anyPolicy node lets the leaf's POLICY_A attach).
        let (store2, chain2) = build_chain(&int_exts, &leaf_exts);
        verify(&store2, &chain2, &PolicyOptions::require(&[POLICY_A])).unwrap();
    }

    #[test]
    fn policy_mapping_translates() {
        // Intermediate asserts POLICY_B and maps POLICY_B -> POLICY_C; leaf
        // asserts POLICY_C. A caller requiring POLICY_B is satisfied because
        // the mapping links the issuer-domain POLICY_B to the leaf's POLICY_C.
        let (store, chain) = build_chain(
            &[
                extension::certificate_policies(&[POLICY_B]),
                extension::policy_mappings(&[(POLICY_B, POLICY_C)]),
            ],
            &[extension::certificate_policies(&[POLICY_C])],
        );
        verify(&store, &chain, &PolicyOptions::require(&[POLICY_B])).unwrap();
        // Requiring POLICY_C is REJECTED: after the mapping, the path is valid
        // for the issuer/anchor-domain policy POLICY_B (which the relying
        // party reasons about); the subject-domain POLICY_C lives only below
        // the mapping and is not what the user-initial-policy-set is matched
        // against (RFC 5280 §6.1.5(g) intersection is in the user domain).
        let (store2, chain2) = build_chain(
            &[
                extension::certificate_policies(&[POLICY_B]),
                extension::policy_mappings(&[(POLICY_B, POLICY_C)]),
            ],
            &[extension::certificate_policies(&[POLICY_C])],
        );
        assert!(verify(&store2, &chain2, &PolicyOptions::require(&[POLICY_C])).is_err());
    }

    #[test]
    fn inhibit_policy_mapping_blocks_translation() {
        // Same mapping shape, but mapping is inhibited from the start. The
        // issuer-domain POLICY_B node is deleted when the mapping would apply,
        // so requiring POLICY_B fails (leaf only carries POLICY_C).
        let (store, chain) = build_chain(
            &[
                extension::certificate_policies(&[POLICY_B]),
                extension::policy_mappings(&[(POLICY_B, POLICY_C)]),
            ],
            &[extension::certificate_policies(&[POLICY_C])],
        );
        let mut opts = PolicyOptions::require(&[POLICY_B]);
        opts.inhibit_policy_mapping = true;
        assert!(verify(&store, &chain, &opts).is_err());
    }

    #[test]
    fn require_explicit_via_cert_policy_constraints() {
        // No initial explicit-policy requirement, but the intermediate carries
        // policyConstraints{requireExplicitPolicy=0}. The leaf lacks the
        // required policy, so the tree is empty and explicit_policy reaches 0
        // → reject. Caller constrains to POLICY_A.
        let (store, chain) = build_chain(
            &[
                extension::certificate_policies(&[POLICY_A]),
                extension::policy_constraints(Some(0), None),
            ],
            &[extension::certificate_policies(&[POLICY_B])],
        );
        // Caller only constrains the policy set (no initial explicit policy);
        // the cert's policyConstraints supplies the explicit requirement.
        let opts = PolicyOptions {
            initial_policies: Some(vec![POLICY_A.to_vec()]),
            require_explicit_policy: false,
            inhibit_policy_mapping: false,
            inhibit_any_policy: false,
        };
        assert!(verify(&store, &chain, &opts).is_err());
        // And when the leaf DOES carry POLICY_A, the same constraint passes.
        let (store2, chain2) = build_chain(
            &[
                extension::certificate_policies(&[POLICY_A]),
                extension::policy_constraints(Some(0), None),
            ],
            &[extension::certificate_policies(&[POLICY_A])],
        );
        verify(&store2, &chain2, &opts).unwrap();
    }

    #[test]
    fn user_set_disjoint_from_chain_is_rejected() {
        // Chain asserts POLICY_A throughout; caller requires POLICY_C only.
        // No intersection → reject.
        let (store, chain) = build_chain(
            &[extension::certificate_policies(&[POLICY_A])],
            &[extension::certificate_policies(&[POLICY_A])],
        );
        assert!(verify(&store, &chain, &PolicyOptions::require(&[POLICY_C])).is_err());
    }

    #[test]
    fn critical_policy_constraints_only_accepted_when_processing() {
        // A critical policyConstraints extension is rejected as an unknown
        // critical extension by the DEFAULT path, but accepted (processed)
        // when policy processing is enabled.
        let crit_pc = {
            let mut e = extension::policy_constraints(Some(0), None);
            e.critical = true;
            e
        };
        let (store, chain) = build_chain(
            &[
                extension::certificate_policies(&[POLICY_A]),
                crit_pc.clone(),
            ],
            &[extension::certificate_policies(&[POLICY_A])],
        );
        // Default path: critical policyConstraints → unknown-critical reject.
        assert!(verify(&store, &chain, &PolicyOptions::none()).is_err());
        // Policy-aware path: processed; chain valid for POLICY_A.
        verify(&store, &chain, &PolicyOptions::require(&[POLICY_A])).unwrap();
    }
}
