// apple-interop: a TLS client and server on Apple's Network.framework for
// the purecrypto interop matrix. Subcommands:
//
//   client --port N [options]    connect (twice with --resume), log, exit
//   server --p12 F [options]     listen on a free port, serve --accept N
//   probe NAME...                which SPI symbols this macOS has
//   version                      the OS version (the TLS stack is the OS's)
//
// Every negotiated parameter goes to --log as `key: value` lines; see
// Connection.swift. Exit status: 0 when every session completed with the
// peer's close_notify, 1 otherwise, 2 on usage.

import Foundation
import Network
import Security

let argv = CommandLine.arguments
guard argv.count >= 2 else { Options.usage() }

switch argv[1] {
case "probe":
    exit(SPI.probe(Array(argv.dropFirst(2))))
case "version":
    let v = ProcessInfo.processInfo.operatingSystemVersion
    print("macOS \(v.majorVersion).\(v.minorVersion).\(v.patchVersion) Network.framework/Security (\(ProcessInfo.processInfo.operatingSystemVersionString))")
    exit(0)
default:
    break
}

let opts = Options.parse(argv)
let queue = DispatchQueue(label: "apple-interop")
let anchors = opts.caFile.map { certificates(fromPEM: $0) } ?? []
let identity = opts.p12File.map { Identity(p12Path: $0, password: opts.p12Password, chainFile: opts.chainFile) }
let payload = opts.sendFile.flatMap { FileManager.default.contents(atPath: $0) }

// Deadline: a stuck handshake must not outlive the runner's patience.
DispatchQueue.global().asyncAfter(deadline: .now() + opts.deadline) {
    stderr("deadline of \(opts.deadline)s reached")
    identity?.cleanup()
    exit(1)
}

signal(SIGTERM) { _ in
    identity?.cleanup()
    exit(1)
}

func runClient(log: Log, earlyData: Data?) -> Int32 {
    let params = makeParameters(opts, identity: identity, anchors: anchors, log: log, queue: queue)
    let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(opts.host), port: NWEndpoint.Port(rawValue: opts.port)!)
    let connection = NWConnection(to: endpoint, using: params)
    let done = DispatchSemaphore(value: 0)
    var status: Int32 = 1
    let session = Session(connection, role: .client, payload: payload, readTimeout: opts.readTimeout,
                          log: log, queue: queue) { code in
        status = code
        done.signal()
    }
    if let early = earlyData {
        // 0-RTT: data queued before `start` goes out with the ClientHello
        // (allowFastOpen); the stack sends it as early data when it holds a
        // ticket that allows it.
        connection.send(content: early, completion: .contentProcessed { e in
            if let e = e { log.line("early data send error: \(e)") } else { log.line("early data sent: \(early.count) bytes") }
        })
    }
    session.start()
    done.wait()
    return status
}

func runServer(log: Log) -> Int32 {
    let params = makeParameters(opts, identity: identity, anchors: anchors, log: log, queue: queue)
    if opts.earlyData != nil {
        params.allowFastOpen = true
    }
    guard let listener = try? NWListener(using: params, on: .any) else { fail("NWListener failed") }
    let done = DispatchSemaphore(value: 0)
    var served = 0
    var failures: Int32 = 0
    var sessions: [Session] = []
    listener.stateUpdateHandler = { state in
        switch state {
        case .ready:
            let port = listener.port?.rawValue ?? 0
            log.line("listening: \(port)")
            if let f = opts.portFile {
                try? "\(port)\n".write(toFile: f, atomically: true, encoding: .utf8)
            }
        case .failed(let e):
            stderr("listener failed: \(e)")
            failures += 1
            done.signal()
        default:
            break
        }
    }
    listener.newConnectionHandler = { connection in
        served += 1
        let n = served
        log.line("--- connection \(n)")
        let session = Session(connection, role: .server, payload: payload, readTimeout: opts.readTimeout,
                              log: log, queue: queue) { code in
            if code != 0 { failures += 1 }
            log.line("--- connection \(n) done (\(code))")
            if n >= opts.accept { done.signal() }
        }
        sessions.append(session)
        session.start()
    }
    listener.start(queue: queue)
    done.wait()
    listener.cancel()
    return failures == 0 ? 0 : 1
}

var status: Int32
switch opts.role {
case .client:
    let log = Log(path: opts.log)
    status = runClient(log: log, earlyData: nil)
    if status == 0 && opts.resume {
        // The second connection, from the same process: the stack resumes
        // with the ticket the first one was issued.
        let log2 = Log(path: opts.log2 ?? (opts.log + ".2"))
        let early = opts.earlyData.flatMap { FileManager.default.contents(atPath: $0) }
        status = runClient(log: log2, earlyData: early)
    }
case .server:
    status = runServer(log: Log(path: opts.log))
}
identity?.cleanup()
exit(status)
