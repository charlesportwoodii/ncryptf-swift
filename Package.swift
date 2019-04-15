// swift-tools-version:5.0
// - Author: Charles R. Portwood II
// - Copyright: (c) 2018-present Charles R. Portwood II
import PackageDescription

let package = Package(
    name: "ncryptf-swift",
    products: [
        .library(name: "ncryptf", targets: ["ncryptf"])
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMinor(from: "1.0.0")),
        .package(url: "https://github.com/jedisct1/swift-sodium.git", .upToNextMinor(from: "0.8.0")),
        .package(url: "https://github.com/onevcat/Rainbow", from: "3.1.5"),
        .package(url: "https://github.com/Bouke/HKDF", .upToNextMinor(from: "3.1.0"))
    ],
    targets: [
        .target(
            name: "ncryptf",
            dependencies: ["Sodium", "HKDF", "CryptoSwift"],
            path: "ncryptf"
        ),
        .testTarget(
            name: "ncryptfTest",
            dependencies: ["ncryptf", "Rainbow"]
        )
    ]
)