// swift-tools-version:5.9
// The `apple-interop` tool: a TLS client and server on Apple's Network.framework
// (NWConnection / NWListener with NWProtocolTLS), driven by the `apple` peer
// adapter next to this package. See README.md in this directory.
import PackageDescription

let package = Package(
    name: "apple-interop",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "apple-interop",
            path: "Sources/apple-interop"
        )
    ],
    swiftLanguageVersions: [.v5]
)
