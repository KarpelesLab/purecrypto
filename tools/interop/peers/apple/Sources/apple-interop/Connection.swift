// One TLS session on an NWConnection, in either role: log the negotiated
// parameters once ready, exchange the application data, end with
// close_notify, wait for the peer's, and report.

import Foundation
import Network
import Security

/// Logs everything `sec_protocol_metadata_t` (and the SPI) says about the
/// session, as the `key: value` lines the adapter's `verify` checks.
func logMetadata(_ connection: NWConnection, log: Log) {
    guard let tlsMeta = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
        log.line("metadata: none")
        return
    }
    let m = tlsMeta.securityProtocolMetadata
    log.line("protocol version: \(versionName(sec_protocol_metadata_get_negotiated_tls_protocol_version(m)))")
    log.line("cipher suite: \(suiteName(sec_protocol_metadata_get_negotiated_tls_ciphersuite(m)))")
    if let alpn = sec_protocol_metadata_get_negotiated_protocol(m) {
        log.line("alpn: \(String(cString: alpn))")
    } else {
        log.line("alpn: none")
    }
    if let copyGroup = SPI.copyGroup, let g = copyGroup(m) {
        log.line("group: \(String(cString: g))")
        free(UnsafeMutablePointer(mutating: g))
    } else if let getGroup = SPI.getGroup, let g = getGroup(m) {
        log.line("group: \(String(cString: g))")
    } else {
        log.line("group: unknown (no SPI)")
    }
    if let resumed = SPI.sessionResumed {
        log.line("resumed: \(resumed(m) ? "yes" : "no")")
    } else {
        log.line("resumed: unknown (no SPI)")
    }
    log.line("early data accepted: \(sec_protocol_metadata_get_early_data_accepted(m) ? "yes" : "no")")
    if let used = SPI.certCompressionUsed, let alg = SPI.certCompressionAlg {
        if used(m) {
            let a = alg(m)
            log.line("certificate compression: \(a == 1 ? "zlib" : a == 2 ? "brotli" : a == 3 ? "zstd" : String(a))")
        } else {
            log.line("certificate compression: none")
        }
    }
    var peerCerts = 0
    var subjects: [String] = []
    _ = sec_protocol_metadata_access_peer_certificate_chain(m) { c in
        peerCerts += 1
        let ref = sec_certificate_copy_ref(c).takeRetainedValue()
        subjects.append((SecCertificateCopySubjectSummary(ref) as String?) ?? "?")
    }
    log.line("peer certificates: \(peerCerts)")
    for s in subjects { log.line("peer certificate subject: \(s)") }
    if let key = sec_protocol_metadata_copy_peer_public_key(m) {
        log.line("peer public key: \((key as DispatchData).count) bytes")
    } else {
        log.line("peer public key: none")
    }
    var ocspBytes = 0
    _ = sec_protocol_metadata_access_ocsp_response(m) { d in
        ocspBytes += (d as DispatchData).count
    }
    log.line("ocsp response: \(ocspBytes > 0 ? "yes (\(ocspBytes) bytes)" : "no")")
    if let sn = sec_protocol_metadata_get_server_name(m) {
        log.line("server name: \(String(cString: sn))")
    }
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
                logMetadata(self.connection, log: self.log)
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

    /// Sends our close_notify (`.finalMessage` on a TLS connection is the
    /// TLS close) and ends the connection once it is out. Nothing the peer
    /// sends after that half-close is observable here (see above), so there
    /// is nothing to wait for.
    private func closeOurSide() {
        guard !closing else { return }
        closing = true
        idleTimer?.cancel()
        log.line("received: \(received.count) bytes")
        connection.send(content: nil, contentContext: .finalMessage, isComplete: true,
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

    private func finish(_ code: Int32) {
        guard !finished else { return }
        finished = true
        idleTimer?.cancel()
        onFinish(code)
    }
}
