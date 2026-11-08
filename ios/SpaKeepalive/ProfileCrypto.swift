import Foundation
import CryptoKit

enum ProfileCrypto {
    static func isEncrypted(_ data: Data) throws -> Bool {
        try FlatJSON.parse(data)["version"] as? Int == 2
    }
    static func unlock(_ data: Data, password: String) throws -> Profile {
        do {
            let e = try FlatJSON.parse(data)
            guard Set(e.keys) == Set(["version","format","kdf","iterations","salt","nonce","ciphertext"]),
                  e["version"] as? Int == 2, e["format"] as? String == "spa-profile-aes256-gcm",
                  e["kdf"] as? String == "pbkdf2-sha256", e["iterations"] as? Int == 600000,
                  let saltText = e["salt"] as? String, let nonceText = e["nonce"] as? String,
                  let cipherText = e["ciphertext"] as? String,
                  !password.isEmpty, password.utf8.count <= 1024 else { throw SPAError.password }
            let salt = try canonicalBase64(saltText, range: 16...16)
            let nonce = try canonicalBase64(nonceText, range: 12...12)
            let ciphertext = try canonicalBase64(cipherText, range: 17...8192)
            var pass = Array(password.utf8); defer { pass.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
            var derived = [UInt8](repeating: 0, count: 32)
            defer { derived.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
            let rc = pass.withUnsafeBytes { raw in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                        raw.baseAddress!.assumingMemoryBound(to: Int8.self), pass.count,
                        saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 600000, &derived, 32)
                }
            }
            guard rc == kCCSuccess else { throw SPAError.password }
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce),
                ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16))
            var plain = try AES.GCM.open(box, using: SymmetricKey(data: derived),
                authenticating: Data("fwknop-keepalive/profile/v2".utf8))
            defer { plain.resetBytes(in: 0..<plain.count) }
            return try Profile.parse(plain)
        } catch { throw SPAError.password }
    }
}
