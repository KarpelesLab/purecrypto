// Command-line options of the apple-interop tool, and the SPI probe.
//
// Everything the `apple` adapter can ask for is a flag here; what the case
// needs is decided in the adapter (shell), this file only parses.

import Foundation
import Network
import Security

enum Role { case client, server }

struct Options {
    var role: Role = .client
    var host = "127.0.0.1"
    var port: UInt16 = 0
    var serverName = "localhost"
    /// The CA certificate (PEM) the peer's chain must anchor to.
    var caFile: String?
    /// Our own identity: a PKCS#12 and its password.
    var p12File: String?
    var p12Password = ""
    /// Extra certificates (PEM) to present after the leaf, e.g. an intermediate.
    var chainFile: String?
    var minVersion: tls_protocol_version_t = .TLSv13
    var maxVersion: tls_protocol_version_t = .TLSv13
    var ciphersuites: [tls_ciphersuite_t] = []
    var alpn: [String] = []
    /// TLS named groups (IANA codepoints) to offer, in order — SPI.
    var groups: [UInt16] = []
    /// Client: request a stapled OCSP response.
    var ocsp = false
    /// Client: a file to send as 0-RTT early data on the resumed connection.
    /// Server: accept early data.
    var earlyData: String?
    /// Client: connect twice (the second connection resumes).
    var resume = false
    /// Client: request the second connection's log here.
    var log2: String?
    /// Server: require and verify a client certificate.
    var clientAuth = false
    /// Server: how many connections to serve before exiting.
    var accept = 1
    /// Server: the file to write the listening port to.
    var portFile: String?
    /// What we send: the client after the handshake, the server after the
    /// client's first data.
    var sendFile: String?
    /// The negotiated-parameter log (key: value lines).
    var log = "/dev/stdout"
    /// Seconds of silence after the last byte before we end the session.
    var readTimeout: Double = 2
    /// Hard deadline for the whole run, in seconds.
    var deadline: Double = 30
    /// Raw public keys (SPI): the SPKI DER files (PEM) accepted from the peer.
    var rpkPeerKeys: [String] = []
    /// Raw public key (SPI): present our own key as a raw public key.
    var rpkSelf = false

    static func usage() -> Never {
        let text = """
        usage: apple-interop client|server|probe|version [options]
          --host H --port N --sni NAME --ca ca.crt --p12 id.p12 --pass PW --chain chain.pem
          --min tls12|tls13 --max tls12|tls13 --suite NAME[,NAME]  --alpn P[,P]
          --group NAME[,NAME] (x25519 p256 p384 p521 x25519mlkem768)
          --ocsp  --early-data FILE|accept  --resume --log2 FILE
          --client-auth  --accept N  --port-file FILE  --send FILE  --log FILE
          --read-timeout SECS  --deadline SECS  --rpk-peer-key FILE  --rpk-self
        """
        FileHandle.standardError.write((text + "\n").data(using: .utf8)!)
        exit(2)
    }

    static func parse(_ argv: [String]) -> Options {
        var o = Options()
        guard argv.count >= 2 else { usage() }
        switch argv[1] {
        case "client": o.role = .client
        case "server": o.role = .server
        default: usage()
        }
        var i = 2
        func value() -> String {
            i += 1
            guard i < argv.count else { usage() }
            return argv[i]
        }
        while i < argv.count {
            switch argv[i] {
            case "--host": o.host = value()
            case "--port": o.port = UInt16(value()) ?? 0
            case "--sni": o.serverName = value()
            case "--ca": o.caFile = value()
            case "--p12": o.p12File = value()
            case "--pass": o.p12Password = value()
            case "--chain": o.chainFile = value()
            case "--min": o.minVersion = version(value())
            case "--max": o.maxVersion = version(value())
            case "--suite": o.ciphersuites = value().split(separator: ",").map { suite(String($0)) }
            case "--alpn": o.alpn = value().split(separator: ",").map(String.init)
            case "--group": o.groups = value().split(separator: ",").map { group(String($0)) }
            case "--ocsp": o.ocsp = true
            case "--early-data": o.earlyData = value()
            case "--resume": o.resume = true
            case "--log2": o.log2 = value()
            case "--client-auth": o.clientAuth = true
            case "--accept": o.accept = Int(value()) ?? 1
            case "--port-file": o.portFile = value()
            case "--send": o.sendFile = value()
            case "--log": o.log = value()
            case "--read-timeout": o.readTimeout = Double(value()) ?? 2
            case "--deadline": o.deadline = Double(value()) ?? 30
            case "--rpk-peer-key": o.rpkPeerKeys.append(value())
            case "--rpk-self": o.rpkSelf = true
            default:
                FileHandle.standardError.write("unknown option \(argv[i])\n".data(using: .utf8)!)
                usage()
            }
            i += 1
        }
        return o
    }

    static func version(_ s: String) -> tls_protocol_version_t {
        switch s {
        case "tls12": return .TLSv12
        case "tls13": return .TLSv13
        default: usage()
        }
    }

    static func suite(_ s: String) -> tls_ciphersuite_t {
        switch s {
        case "aes128gcm", "TLS_AES_128_GCM_SHA256": return .AES_128_GCM_SHA256
        case "aes256gcm", "TLS_AES_256_GCM_SHA384": return .AES_256_GCM_SHA384
        case "chacha20", "TLS_CHACHA20_POLY1305_SHA256": return .CHACHA20_POLY1305_SHA256
        // TLS 1.2 ECDHE-ECDSA suites, for the fallback case.
        case "ecdhe-ecdsa-aes128gcm": return .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        default: usage()
        }
    }

    /// RFC 8446 §4.2.7 / draft-ietf-tls-ecdhe-mlkem codepoints.
    static func group(_ s: String) -> UInt16 {
        switch s {
        case "p256", "secp256r1": return 0x0017
        case "p384", "secp384r1": return 0x0018
        case "p521", "secp521r1": return 0x0019
        case "x25519": return 0x001D
        case "x25519mlkem768": return 0x11EC
        case "secp256r1mlkem768": return 0x11EB
        default: usage()
        }
    }
}

// MARK: - names for the log

func versionName(_ v: tls_protocol_version_t) -> String {
    switch v {
    case .TLSv12: return "TLSv1.2"
    case .TLSv13: return "TLSv1.3"
    case .DTLSv12: return "DTLSv1.2"
    default: return String(format: "0x%04x", v.rawValue)
    }
}

func suiteName(_ s: tls_ciphersuite_t) -> String {
    switch s {
    case .AES_128_GCM_SHA256: return "TLS_AES_128_GCM_SHA256"
    case .AES_256_GCM_SHA384: return "TLS_AES_256_GCM_SHA384"
    case .CHACHA20_POLY1305_SHA256: return "TLS_CHACHA20_POLY1305_SHA256"
    case .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: return "ECDHE-ECDSA-AES128-GCM-SHA256"
    case .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: return "ECDHE-ECDSA-AES256-GCM-SHA384"
    case .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: return "ECDHE-ECDSA-CHACHA20-POLY1305"
    case .ECDHE_RSA_WITH_AES_128_GCM_SHA256: return "ECDHE-RSA-AES128-GCM-SHA256"
    case .ECDHE_RSA_WITH_AES_256_GCM_SHA384: return "ECDHE-RSA-AES256-GCM-SHA384"
    case .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: return "ECDHE-RSA-CHACHA20-POLY1305"
    default: return String(format: "0x%04x", s.rawValue)
    }
}

// MARK: - SPI
//
// Apple's TLS stack exposes what the matrix needs beyond the public
// `sec_protocol_options_*` API through SPI declared in the open-source
// Security project's SecProtocolPriv.h (apple-oss-distributions/Security):
// named groups, the PQ hybrid, session-resumption and certificate-compression
// facts in the metadata, early data, raw public keys. Each is looked up with
// dlsym and used only when present; `apple-interop probe NAME` tells the
// adapter which ones this macOS has, so it can SKIP with a reason.

let RTLD_DEFAULT_HANDLE = UnsafeMutableRawPointer(bitPattern: -2)

func spi<T>(_ name: String, _ type: T.Type) -> T? {
    guard let sym = dlsym(RTLD_DEFAULT_HANDLE, name) else { return nil }
    return unsafeBitCast(sym, to: type)
}

typealias OptionsBoolFn = @convention(c) (sec_protocol_options_t, Bool) -> Void
typealias OptionsU16Fn = @convention(c) (sec_protocol_options_t, UInt16) -> Void
typealias OptionsCFArrayFn = @convention(c) (sec_protocol_options_t, CFArray) -> Void
typealias MetadataBoolFn = @convention(c) (sec_protocol_metadata_t) -> Bool
typealias MetadataU16Fn = @convention(c) (sec_protocol_metadata_t) -> UInt16
typealias MetadataCStringFn = @convention(c) (sec_protocol_metadata_t) -> UnsafePointer<CChar>?

enum SPI {
    static let setEarlyData = spi("sec_protocol_options_set_tls_early_data_enabled", OptionsBoolFn.self)
    static let appendGroup = spi("sec_protocol_options_append_tls_key_exchange_group", OptionsU16Fn.self)
    static let setServerRpk = spi("sec_protocol_options_set_server_raw_public_key_certificates", OptionsCFArrayFn.self)
    static let setClientRpk = spi("sec_protocol_options_set_client_raw_public_key_certificates", OptionsCFArrayFn.self)
    static let sessionResumed = spi("sec_protocol_metadata_get_session_resumed", MetadataBoolFn.self)
    static let copyGroup = spi("sec_protocol_metadata_copy_tls_negotiated_group", MetadataCStringFn.self)
    static let getGroup = spi("sec_protocol_metadata_get_tls_negotiated_group", MetadataCStringFn.self)
    static let certCompressionUsed = spi("sec_protocol_metadata_get_tls_certificate_compression_used", MetadataBoolFn.self)
    static let certCompressionAlg = spi("sec_protocol_metadata_get_tls_certificate_compression_algorithm", MetadataU16Fn.self)

    /// `probe NAME...`: one `NAME: yes|no` line each; exit 0 if all present.
    static func probe(_ names: [String]) -> Int32 {
        var missing: Int32 = 0
        for n in names {
            let present = dlsym(RTLD_DEFAULT_HANDLE, n) != nil
            print("\(n): \(present ? "yes" : "no")")
            if !present { missing = 1 }
        }
        return missing
    }
}
