// swift-tools-version:4.1
// - Author: Charles R. Portwood II
// - Copyright: (c) 2018-present Charles R. Portwood II
import PackageDescription

let package = Package(
    name: "ncryptf-swift",
    products: [
        .library(name: "ncryptf", targets: ["ncryptf"])
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMinor(from: "0.13.0")),
        .package(url: "https://github.com/jedisct1/swift-sodium.git", .upToNextMinor(from: "0.7.0")),
        .package(url: "https://github.com/Alamofire/Alamofire.git", .upToNextMinor(from: "4.7.3")),
        .package(url: "https://github.com/onevcat/Rainbow", from: "3.0.0")
    ],
    targets: [
        .target(
            name: "ncryptf",
            dependencies: ["Sodium", "CryptoSwift"],
            path: "ncryptf"
        ),
        .testTarget(
            name: "ncryptfTest",
            dependencies: ["ncryptf", "Alamofire", "Rainbow"]
        )
    ]
)