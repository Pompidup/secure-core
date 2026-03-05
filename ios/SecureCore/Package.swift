// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "SecureCore",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(name: "SecureCore", targets: ["SecureCore"]),
    ],
    targets: [
        .target(
            name: "SecureCore",
            path: "Sources/SecureCore"
        ),
        .testTarget(
            name: "SecureCoreTests",
            dependencies: ["SecureCore"],
            path: "Tests/SecureCoreTests"
        ),
    ]
)
