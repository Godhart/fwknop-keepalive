import XCTest
@testable import SpaKeepalive

final class ProfileTests: XCTestCase {
    func fixture(_ name: String) throws -> Data {
        let url = try XCTUnwrap(Bundle(for: Self.self).url(forResource: name, withExtension: "json"))
        return try Data(contentsOf: url)
    }
    func testPythonEncryptionAndWrongPassword() throws {
        let encrypted = try fixture("encrypted")
        let plain = try Profile.parse(fixture("plain"))
        XCTAssertTrue(try ProfileCrypto.isEncrypted(encrypted))
        XCTAssertEqual(try ProfileCrypto.unlock(encrypted, password: "пароль 🔑 Test 123"), plain)
        XCTAssertThrowsError(try ProfileCrypto.unlock(encrypted, password: "wrong"))
        var e = try FlatJSON.parse(encrypted); e["iterations"] = 1
        XCTAssertThrowsError(try ProfileCrypto.unlock(JSONSerialization.data(withJSONObject: e), password: "пароль 🔑 Test 123"))
        e = try FlatJSON.parse(encrypted)
        var bytes = Data(base64Encoded: e["ciphertext"] as! String)!
        bytes[0] ^= 1; e["ciphertext"] = bytes.base64EncodedString()
        XCTAssertThrowsError(try ProfileCrypto.unlock(JSONSerialization.data(withJSONObject: e), password: "пароль 🔑 Test 123"))
    }
    func testStrictProfileValidation() throws {
        let data = try fixture("plain")
        XCTAssertFalse(try ProfileCrypto.isEncrypted(data))
        XCTAssertThrowsError(try FlatJSON.parse(Data(#"{"version":1,"version":1}"#.utf8)))
        XCTAssertThrowsError(try FlatJSON.parse(Data(#"{"version":1,}"#.utf8)))
        XCTAssertThrowsError(try FlatJSON.parse(Data(#"{"version":1.0}"#.utf8)))
        XCTAssertThrowsError(try FlatJSON.parse(Data(#"{"version":true}"#.utf8)))
        for (key, value) in [("access", "tcp/70000"), ("allow_ip", "01.2.3.4"), ("key_base64", "invalid")] {
            var object = try FlatJSON.parse(data); object[key] = value
            XCTAssertThrowsError(try Profile.parse(JSONSerialization.data(withJSONObject: object)))
        }
        var object = try FlatJSON.parse(data); object["interval_seconds"] = 60
        XCTAssertThrowsError(try Profile.parse(JSONSerialization.data(withJSONObject: object)))
        object = try FlatJSON.parse(data); object["unknown"] = "no"
        XCTAssertThrowsError(try Profile.parse(JSONSerialization.data(withJSONObject: object)))
    }
    func testNativePacketsAreFresh() throws {
        let profile = try Profile.parse(fixture("plain"))
        let a = try SPASender.packet(profile), b = try SPASender.packet(profile)
        XCTAssertNotEqual(a, b)
        XCTAssertGreaterThan(a.count, 100)
        XCTAssertFalse(String(decoding: a, as: UTF8.self).contains(profile.key_base64))
    }
    @MainActor func testIndependentProfilesAndForegroundStop() throws {
        var disk: [SavedProfile] = []
        let model = AppModel(load: { disk }, save: { disk = $0 })
        let p = try Profile.parse(fixture("plain"))
        try model.add(p); try model.add(p)
        let a = model.profiles[0].id, b = model.profiles[1].id
        XCTAssertNotEqual(a, b)
        model.setActive(true)
        model.startLoop(a); model.startLoop(b)
        XCTAssertEqual(model.loops, Set([a,b]))
        model.stop(a)
        XCTAssertEqual(model.loops, Set([b]))
        model.setActive(false)
        XCTAssertTrue(model.loops.isEmpty); XCTAssertTrue(model.sending.isEmpty)
        model.setActive(true)
        XCTAssertTrue(model.loops.isEmpty) // no silent restart on return
        model.remove(a)
        XCTAssertEqual(disk.map(\.id), [b])
        XCTAssertEqual(AppModel(load: { disk }, save: { disk = $0 }).profiles.count, 1)
    }
    @MainActor func testStorageFailureAndLimit() throws {
        let p = try Profile.parse(fixture("plain"))
        var writes = 0
        let broken = AppModel(load: { throw SPAError.storage }, save: { _ in writes += 1 })
        XCTAssertThrowsError(try broken.add(p))
        XCTAssertEqual(writes, 0)
        let model = AppModel(load: { [] }, save: { _ in })
        for _ in 0..<16 { try model.add(p) }
        XCTAssertThrowsError(try model.add(p))
        XCTAssertEqual(model.profiles.count, 16)
    }
    func testOnlyHTTPSWebsites() {
        XCTAssertNotNil(AppModel.websiteURL("https://example.org/path"))
        for bad in ["http://example.org", "javascript:alert(1)", "https://user:secret@example.org", "file:///tmp/test"] {
            XCTAssertNil(AppModel.websiteURL(bad))
        }
    }
}
