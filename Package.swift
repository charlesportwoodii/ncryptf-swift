// swift-tools-version:4.1
// - Author: Charles R. Portwood II
// - Copyright: (c) 2018-present Charles R. Portwood II
import PackageDescription

let package = Package(
    name: "KDFAuth",
    products: [
        .library(name: "KDFAuth", targets: ["KDFAuth"])
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMinor(from: "0.9.0")),
        .package(url: "https://github.com/jedisct1/swift-sodium.git", .branch("master")),
//        .package(url: "https://github.com/Alamofire/Alamofire.git", from: "4.0.0"),
    ],
    targets: [
        .target(
            name: "KDFAuth",
            dependencies: ["Sodium", "CryptoSwift"],
            path: "KDFAuth"
        ),
        .testTarget(
            name: "KDFAuthTest",
            dependencies: ["KDFAuth" /*, "Alamofire" */]
        )
    ]
)