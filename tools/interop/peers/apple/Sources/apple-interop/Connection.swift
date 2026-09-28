// One TLS session on an NWConnection, in either role: exchange the
// application data, log the negotiated parameters once the connection has
// gone quiet, end with close_notify, and report.

import Foundation
import Network
import Security

/// What `sec_protocol_metadata_t` (and the SPI) says about the session, as
/// the `key: value` lines the adapter's `verify` checks.
///
/// The metadata is only safe to read while the stack is idle. Its accessors
/// take no lock, and the stack rewrites the object on its own thread after
/// the handshake: for every NewSessionTicket a client's stack rebuilds the
/// session's state (`boringssl_context_new_session_handler`), and the
/// tickets arrive right behind the handshake — just when `.ready` reaches
/// our queue. A read that falls into that window gets the scalars
/// (version, suite, resumed, ...) but no group, no peer chain or no public
/// key, or crashes on an object the stack has just released. So `Session`
/// reads when the exchange is over; `missing` names what a read did not
/// get although the handshake must have produced it, so that the caller
/// can tell "not there at the moment" from a value.
struct Facts {
    var lines: [String] = []
    var missing: [String] = []
}

func readFacts(_ connection: NWConnection) -> Facts? {
    guard let tlsMeta = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
        return nil
    }
    let m = tlsMeta.securityProtocolMetadata
    var f = Facts()
    let version = sec_protocol_metadata_get_negotiated_tls_protocol_version(m)
    f.lines.append("protocol version: \(versionName(version))")
    f.lines.append("cipher suite: \(suiteName(sec_protocol_metadata_get_negotiated_tls_ciphersuite(m)))")
    if let alpn = sec_protocol_metadata_get_negotiated_protocol(m) {
        f.lines.append("alpn: \(String(cString: alpn))")
    } else {
        f.lines.append("alpn: none")
    }
    // Three answers, never to be confused: the group's name; `unavailable`
    // (the SPI is there and returned nothing — every TLS 1.3 handshake has
    // a group, so the read fell into a rewrite); no such SPI on this macOS.
    if SPI.copyGroup == nil && SPI.getGroup == nil {
        f.lines.append("group: unknown (no SPI)")
    } else if let g = negotiatedGroup(m) {
        f.lines.append("group: \(g)")
    } else {
        f.lines.append("group: unavailable")
        if version == .TLSv13 { f.missing.append("group") }
    }
    if let resumed = SPI.sessionResumed {
        f.lines.append("resumed: \(resumed(m) ? "yes" : "no")")
    } else {
        f.lines.append("resumed: unknown (no SPI)")
    }
    f.lines.append("early data accepted: \(sec_protocol_metadata_get_early_data_accepted(m) ? "yes" : "no")")
    if let used = SPI.certCompressionUsed, let alg = SPI.certCompressionAlg {
        if used(m) {
            let a = alg(m)
            f.lines.append("certificate compression: \(a == 1 ? "zlib" : a == 2 ? "brotli" : a == 3 ? "zstd" : String(a))")
        } else {
            f.lines.append("certificate compression: none")
        }
    } else {
        f.lines.append("certificate compression: unknown (no SPI)")
    }
    var peerCerts = 0
    var subjects: [String] = []
    _ = sec_protocol_metadata_access_peer_certificate_chain(m) { c in
        peerCerts += 1
        let ref = sec_certificate_copy_ref(c).takeRetainedValue()
        subjects.append((SecCertificateCopySubjectSummary(ref) as String?) ?? "?")
    }
    f.lines.append("peer certificates: \(peerCerts)")
    for s in subjects { f.lines.append("peer certificate subject: \(s)") }
    if let key = sec_protocol_metadata_copy_peer_public_key(m) {
        f.lines.append("peer public key: \((key as DispatchData).count) bytes")
    } else {
        f.lines.append("peer public key: none")
        // A chain without its key is a read that fell between the two.
        if peerCerts > 0 { f.missing.append("peer public key") }
    }
    var ocspBytes = 0
    _ = sec_protocol_metadata_access_ocsp_response(m) { d in
        ocspBytes += (d as DispatchData).count
    }
    f.lines.append("ocsp response: \(ocspBytes > 0 ? "yes (\(ocspBytes) bytes)" : "no")")
    if let sn = sec_protocol_metadata_get_server_name(m) {
        f.lines.append("server name: \(String(cString: sn))")
    }
    return f
}

/// The negotiated group's name through whichever SPI this macOS has.
func negotiatedGroup(_ m: sec_protocol_metadata_t) -> String? {
    if let copyGroup = SPI.copyGroup {
        guard let g = copyGroup(m) else { return nil }
        defer { free(UnsafeMutablePointer(mutating: g)) }
        return String(cString: g)
    }
    if let getGroup = SPI.getGroup, let g = getGroup(m) {
        return String(cString: g)
    }
    return nil
}

/// Drives one connection to completion; `finished` is signalled once.
final class Session {
    let connection: NWConnection
    let log: Log
    let queue: DispatchQueue
    let readTimeout: Double
    /// What we send: the client right after the handshake, the server once
    /// the client's first data is in (so a purecrypto-initiated KeyUpdate
    /// has arrived before the write that carries the reply).
    let payload: Data?
    let role: Role
    let onFinish: (Int32) -> Void

    private var received = Data()
    private var sent = false
    private var closing = false
    private var finished = false
    private var idleTimer: DispatchWorkItem?
    private var peerClosed = false
    private var closeSent = false
    /// `.ready` was seen: the handshake is over.
    private var ready = false
    private var factsLogged = false
    private var factsReads = 0

    init(_ connection: NWConnection, role: Role, payload: Data?, readTimeout: Double,
         log: Log, queue: DispatchQueue, onFinish: @escaping (Int32) -> Void) {
        self.connection = connection
        self.role = role
        self.payload = payload
        self.readTimeout = readTimeout
        self.log = log
        self.queue = queue
        self.onFinish = onFinish
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .waiting(let e):
                // Network.framework would retry; for a loopback test the
                // first failure is the answer.
                self.log.line("state: waiting (\(e))")
                self.connection.cancel()
            case .preparing:
                break
            case .ready:
                self.log.line("state: ready")
                self.ready = true
                if self.role == .client {
                    self.sendPayload()
                    self.receiveLoop()
                }
            case .failed(let e):
                self.log.line("state: failed (\(e))")
                self.finish(1)
            case .cancelled:
                self.log.line("state: cancelled")
                self.finish(self.closeSent ? 0 : 1)
            default:
                break
            }
        }
        connection.start(queue: queue)
        // A server reads from the start: with 0-RTT, early data is
        // delivered before the connection is ready (and the handshake
        // waits for the read).
        if role == .server {
            receiveLoop()
        }
    }

    private func sendPayload() {
        guard !sent, let payload = payload else { return }
        sent = true
        connection.send(content: payload, completion: .contentProcessed { [weak self] e in
            if let e = e { self?.log.line("send error: \(e)") } else { self?.log.line("sent: \(payload.count) bytes") }
        })
        armIdleTimer()
    }

    /// Logs the negotiated parameters, once, then runs `then`.
    ///
    /// Called when the exchange is over — the client has heard nothing for
    /// `readTimeout`, the server has the client's close — and so with the
    /// stack idle: not from the `.ready` handler, which runs while the
    /// stack is still working on the metadata (see `Facts`). Should a read
    /// come back short all the same, it is repeated (10 ms apart, for a
    /// second at most) and the log says so; what is missing after that is
    /// logged as missing (`group: unavailable`), which `verify` does not
    /// take for the group.
    private func logFacts(then: @escaping () -> Void) {
        guard ready, !factsLogged else {
            then()
            return
        }
        let facts = readFacts(connection)
        factsReads += 1
        if let f = facts, !f.missing.isEmpty, !finished, factsReads < 100 {
            queue.asyncAfter(deadline: .now() + 0.01) { [weak self] in self?.logFacts(then: then) }
            return
        }
        factsLogged = true
        if let f = facts {
            if factsReads > 1 {
                let what = f.missing.isEmpty ? "complete" : "without \(f.missing.joined(separator: ", "))"
                log.line("metadata: \(what) after \(factsReads) reads")
            }
            for l in f.lines { log.line(l) }
        } else {
            log.line("metadata: none")
        }
        then()
    }

    private func receiveLoop() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }
            if let data = data, !data.isEmpty {
                self.received.append(data)
                for line in String(decoding: data, as: UTF8.self).split(separator: "\n") {
                    self.log.line("data: \(line.count > 80 ? String(line.prefix(80)) + "…(\(line.count) chars)" : String(line))")
                }
                if self.role == .server {
                    self.sendPayload()
                }
                self.armIdleTimer()
            }
            if let error = error {
                self.log.line("receive error: \(error)")
                self.finish(1)
                return
            }
            if isComplete {
                // The peer ended the session. Network.framework surfaces a
                // TLS close_notify and a bare TCP FIN the same way (and
                // synthesises one on cancel), so this only says the peer
                // closed first; the purecrypto side's `close_notify:` line
                // is the one that tells the two apart.
                if !self.closing {
                    self.peerClosed = true
                    self.log.line("peer closed: yes")
                    self.closeOurSide()
                }
                return
            }
            self.receiveLoop()
        }
    }

    /// After `readTimeout` of silence the client ends the session; the
    /// server waits for the client's close.
    private func armIdleTimer() {
        idleTimer?.cancel()
        guard role == .client else { return }
        let item = DispatchWorkItem { [weak self] in self?.closeOurSide() }
        idleTimer = item
        queue.asyncAfter(deadline: .now() + readTimeout, execute: item)
    }

    /// Logs the negotiated parameters (the exchange is over, the stack is
    /// idle), then sends our close_notify (`.finalMessage` on a TLS
    /// connection is the TLS close) and ends the connection once it is
    /// out. Nothing the peer sends after that half-close is observable
    /// here (see above), so there is nothing to wait for.
    private func closeOurSide() {
        guard !closing else { return }
        closing = true
        idleTimer?.cancel()
        logFacts { [weak self] in
            guard let self = self, !self.finished else { return }
            self.log.line("received: \(self.received.count) bytes")
            self.connection.send(content: nil, contentContext: .finalMessage, isComplete: true,
                                 completion: .contentProcessed { [weak self] e in
                guard let self = self else { return }
                if let e = e {
                    self.log.line("close send error: \(e)")
                } else {
                    self.log.line("close_notify: sent")
                    self.closeSent = true
                }
                self.connection.cancel()
            })
        }
    }

    private func finish(_ code: Int32) {
        guard !finished else { return }
        finished = true
        idleTimer?.cancel()
        // The connection ended before its close (or while a read was being
        // repeated): log what the stack says now rather than nothing.
        logFacts {}
        onFinish(code)
    }
}
