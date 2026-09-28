// Identity, anchors and the TLS options built from the case: the part of the
// tool that talks to the Security framework.

import Foundation
import Network
import Security

// MARK: - log

/// The `key: value` log the adapter's `verify` greps. Lines are appended
/// synchronously, so a crash still leaves what was learned.
final class Log {
    private let handle: FileHandle
    private let lock = NSLock()

    init(path: String) {
        if path == "/dev/stdout" {
            handle = FileHandle.standardOutput
        } else {
            FileManager.default.createFile(atPath: path, contents: nil)
            guard let h = FileHandle(forWritingAtPath: path) else {
                fail("cannot open log \(path)")
            }
            handle = h
        }
    }

    private let start = Date()
    private let timestamps = ProcessInfo.processInfo.environment["APPLE_INTEROP_TS"] != nil

    func line(_ s: String) {
        lock.lock()
        let prefix = timestamps ? String(format: "[%6.3f] ", Date().timeIntervalSince(start)) : ""
        handle.write((prefix + s + "\n").data(using: .utf8)!)
        lock.unlock()
    }
}

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write("apple-interop: \(msg)\n".data(using: .utf8)!)
    exit(1)
}

func stderr(_ msg: String) {
    FileHandle.standardError.write("apple-interop: \(msg)\n".data(using: .utf8)!)
}

// MARK: - certificates

/// Every CERTIFICATE block of a PEM file.
func certificates(fromPEM path: String) -> [SecCertificate] {
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
        fail("cannot read \(path)")
    }
    var out: [SecCertificate] = []
    var b64 = ""
    var inside = false
    for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
        if line.hasPrefix("-----BEGIN CERTIFICATE-----") {
            inside = true
            b64 = ""
        } else if line.hasPrefix("-----END CERTIFICATE-----") {
            inside = false
            guard let der = Data(base64Encoded: b64),
                let cert = SecCertificateCreateWithData(nil, der as CFData)
            else { fail("\(path): a certificate did not parse") }
            out.append(cert)
        } else if inside {
            b64 += line.trimmingCharacters(in: .whitespaces)
        }
    }
    if out.isEmpty { fail("\(path): no CERTIFICATE block") }
    return out
}

/// The DER of a `PUBLIC KEY` PEM (SubjectPublicKeyInfo), for the raw-public-key SPI.
func spki(fromPEM path: String) -> Data {
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
        fail("cannot read \(path)")
    }
    var b64 = ""
    var inside = false
    for line in text.split(separator: "\n") {
        if line.hasPrefix("-----BEGIN PUBLIC KEY-----") {
            inside = true
        } else if line.hasPrefix("-----END PUBLIC KEY-----") {
            break
        } else if inside {
            b64 += line.trimmingCharacters(in: .whitespaces)
        }
    }
    guard let der = Data(base64Encoded: b64) else { fail("\(path): no PUBLIC KEY block") }
    return der
}

// MARK: - identity

/// Our identity: the PKCS#12 imported into a throwaway file keychain (the
/// only public way to get a `SecIdentity` on macOS), deleted at exit.
final class Identity {
    let identity: sec_identity_t
    let secIdentity: SecIdentity
    let certificates: [SecCertificate]
    private var keychain: SecKeychain?
    private let keychainPath: String

    init(p12Path: String, password: String, chainFile: String?) {
        guard let p12 = FileManager.default.contents(atPath: p12Path) else {
            fail("cannot read \(p12Path)")
        }
        keychainPath = NSTemporaryDirectory() + "apple-interop-\(getpid())-\(UInt32.random(in: 0...UInt32.max)).keychain-db"
        let kcPassword = "apple-interop"
        var kc: SecKeychain?
        var status = SecKeychainCreate(keychainPath, UInt32(kcPassword.utf8.count), kcPassword, false, nil, &kc)
        guard status == errSecSuccess, let keychain = kc else {
            fail("SecKeychainCreate: \(status)")
        }
        self.keychain = keychain
        status = SecKeychainUnlock(keychain, UInt32(kcPassword.utf8.count), kcPassword, true)
        guard status == errSecSuccess else { fail("SecKeychainUnlock: \(status)") }

        var items: CFArray?
        let options: [String: Any] = [
            kSecImportExportPassphrase as String: password,
            kSecImportExportKeychain as String: keychain,
        ]
        status = SecPKCS12Import(p12 as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess else {
            let msg = SecCopyErrorMessageString(status, nil).map { $0 as String } ?? ""
            SecKeychainDelete(keychain)
            try? FileManager.default.removeItem(atPath: keychainPath)
            fail("SecPKCS12Import(\(p12Path)): \(status) \(msg)")
        }
        guard let first = (items as? [[String: Any]])?.first,
            let idRef = first[kSecImportItemIdentity as String]
        else {
            SecKeychainDelete(keychain)
            try? FileManager.default.removeItem(atPath: keychainPath)
            fail("SecPKCS12Import(\(p12Path)): no identity in the archive")
        }
        // swiftlint:disable:next force_cast
        let secIdentity = idRef as! SecIdentity
        self.secIdentity = secIdentity
        var chain: [SecCertificate] = []
        if let chainFile = chainFile {
            chain = apple_interop.certificates(fromPEM: chainFile)
        }
        certificates = chain
        if chain.isEmpty {
            guard let id = sec_identity_create(secIdentity) else { fail("sec_identity_create failed") }
            identity = id
        } else {
            guard let id = sec_identity_create_with_certificates(secIdentity, chain as CFArray) else {
                fail("sec_identity_create_with_certificates failed")
            }
            identity = id
        }
    }

    func cleanup() {
        if let kc = keychain {
            SecKeychainDelete(kc)
            keychain = nil
        }
        try? FileManager.default.removeItem(atPath: keychainPath)
    }

    deinit { cleanup() }
}

// MARK: - trust

/// Evaluates the peer's chain against our CA only, logging the verdict.
/// Anchoring to the case's CA is the whole point: the runner's PKI is not
/// in any system trust store, and a `localhost` leaf must still pass the
/// SSL policy the stack attached (hostname for a client, client-auth for a
/// server).
func evaluate(_ trustRef: sec_trust_t, anchors: [SecCertificate], log: Log) -> Bool {
    let trust = sec_trust_copy_ref(trustRef).takeRetainedValue()
    SecTrustSetAnchorCertificates(trust, anchors as CFArray)
    SecTrustSetAnchorCertificatesOnly(trust, true)
    var error: CFError?
    let ok = SecTrustEvaluateWithError(trust, &error)
    let count = SecTrustGetCertificateCount(trust)
    if ok {
        log.line("verify: ok (\(count) certificate(s))")
    } else {
        let msg = (error as Error?)?.localizedDescription ?? "unknown"
        log.line("verify: failed (\(count) certificate(s)): \(msg)")
    }
    return ok
}

// MARK: - TLS options

/// Builds the NWParameters (TCP + TLS) for the role from the options.
func makeParameters(_ o: Options, identity: Identity?, anchors: [SecCertificate], log: Log,
                    queue: DispatchQueue) -> NWParameters {
    let tls = NWProtocolTLS.Options()
    let so = tls.securityProtocolOptions

    sec_protocol_options_set_min_tls_protocol_version(so, o.minVersion)
    sec_protocol_options_set_max_tls_protocol_version(so, o.maxVersion)
    for s in o.ciphersuites {
        sec_protocol_options_append_tls_ciphersuite(so, s)
    }
    for p in o.alpn {
        sec_protocol_options_add_tls_application_protocol(so, p)
    }
    if o.role == .client {
        sec_protocol_options_set_tls_server_name(so, o.serverName)
        if o.ocsp {
            sec_protocol_options_set_tls_ocsp_enabled(so, true)
        }
    } else {
        // Tickets and resumption explicitly on for the server too.
        sec_protocol_options_set_tls_tickets_enabled(so, true)
        sec_protocol_options_set_tls_resumption_enabled(so, true)
    }
    sec_protocol_options_set_tls_renegotiation_enabled(so, false)
    if !o.groups.isEmpty {
        guard let append = SPI.appendGroup else { fail("group pinning needs the key-exchange-group SPI") }
        for g in o.groups { append(so, g) }
    }
    if o.earlyData != nil || (o.role == .client && o.resume) {
        // Observed on macOS 26: a client caches the session (and so resumes
        // on the next connection) only with early data enabled; with it
        // enabled and nothing queued before `start`, no early data is
        // offered. So --resume turns it on too.
        guard let set = SPI.setEarlyData else { fail("early data needs the early-data SPI") }
        set(so, true)
    }
    if !o.rpkPeerKeys.isEmpty {
        let keys = o.rpkPeerKeys.map { spki(fromPEM: $0) as CFData } as CFArray
        let set = o.role == .client ? SPI.setServerRpk : SPI.setClientRpk
        guard let set = set else { fail("raw public keys need the SPI") }
        set(so, keys)
    }
    if o.rpkSelf {
        // Our own raw public key: the SPKI of the identity's certificate.
        guard let identity = identity else { fail("--rpk-self needs --p12") }
        var leafRef: SecCertificate?
        guard SecIdentityCopyCertificate(identity.secIdentity, &leafRef) == errSecSuccess, let leaf = leafRef else {
            fail("--rpk-self: no certificate in the identity")
        }
        let set = o.role == .client ? SPI.setClientRpk : SPI.setServerRpk
        guard let set = set else { fail("raw public keys need the SPI") }
        set(so, [certificateSPKI(leaf) as CFData] as CFArray)
    }

    if let identity = identity {
        if o.role == .server {
            sec_protocol_options_set_local_identity(so, identity.identity)
        } else {
            // The client presents its identity when asked (CertificateRequest).
            sec_protocol_options_set_challenge_block(so, { _, complete in
                log.line("challenge: client certificate requested")
                complete(identity.identity)
            }, queue)
        }
    }

    if o.role == .server && o.clientAuth {
        sec_protocol_options_set_peer_authentication_required(so, true)
    }
    if !anchors.isEmpty {
        sec_protocol_options_set_verify_block(so, { _, trust, complete in
            complete(evaluate(trust, anchors: anchors, log: log))
        }, queue)
    } else if !o.rpkPeerKeys.isEmpty {
        // A raw public key has no chain: the SPI matches it against the
        // allowlist; the block only records that the stack asked.
        sec_protocol_options_set_verify_block(so, { _, _, complete in
            log.line("verify: raw public key (allowlist)")
            complete(true)
        }, queue)
    }

    let params = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
    params.allowLocalEndpointReuse = true
    if o.role == .client && o.earlyData != nil {
        params.allowFastOpen = true
    }
    return params
}

/// The SubjectPublicKeyInfo DER of a certificate, cut out of its DER
/// (`SecKeyCopyExternalRepresentation` is not SPKI for EC keys).
func certificateSPKI(_ cert: SecCertificate) -> Data {
    let der = SecCertificateCopyData(cert) as Data
    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version, serial,
    // sigalg, issuer, validity, subject, spki, ... } ... }: skip six fields
    // of the TBS after the optional version.
    var p = 0
    func header() -> (tag: UInt8, len: Int, start: Int) {
        let tag = der[p]
        var len = Int(der[p + 1])
        var hl = 2
        if len & 0x80 != 0 {
            let n = len & 0x7f
            len = 0
            for k in 0..<n { len = (len << 8) | Int(der[p + 2 + k]) }
            hl = 2 + n
        }
        return (tag, len, p + hl)
    }
    var h = header()  // Certificate
    p = h.start
    h = header()  // TBSCertificate
    p = h.start
    h = header()
    if h.tag == 0xA0 {  // version
        p = h.start + h.len
        h = header()
    }
    // serial, sigalg, issuer, validity, subject
    for _ in 0..<5 {
        p = h.start + h.len
        h = header()
    }
    p = h.start + h.len  // now at spki
    h = header()
    return der.subdata(in: p..<(h.start + h.len))
}
