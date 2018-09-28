// swift-tools-version:4.2
// - Author: Charles R. Portwood II
// - Copyright: (c) 2018-present Charles R. Portwood II
import PackageDescription

let package = Package(
    name: "ncryptf-swift",
    products: [
        .library(name: "ncryptf", targets: ["ncryptf"])
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMinor(from: "0.9.0")),
        .package(url: "https://github.com/jedisct1/swift-sodium.git", .branch("master"))
    ],
    targets: [
        .target(
            name: "ncryptf",
            dependencies: ["Sodium", "CryptoSwift"],
            path: "ncryptf"
        ),
        .testTarget(
            name: "ncryptfTest",
            dependencies: ["ncryptf"]
        )
    ]
)