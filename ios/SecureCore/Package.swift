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
    dependencies: [
        .package(url: "https://github.com/groue/GRDB.swift.git", from: "6.0.0"),
    ],
    targets: [
        .target(
            name: "SecureCore",
            dependencies: [
                .product(name: "GRDB", package: "GRDB.swift"),
            ],
            path: "Sources/SecureCore"
        ),
        .testTarget(
            name: "SecureCoreTests",
            dependencies: ["SecureCore"],
            path: "Tests/SecureCoreTests"
        ),
    ]
)
