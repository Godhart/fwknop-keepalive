import Foundation
import Security

enum ProfileStore {
    private static let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "org.example.spakeepalive.profiles",
        kSecAttrAccount as String: "profiles-v1",
        kSecAttrSynchronizable as String: false
    ]
    static func load() throws -> [SavedProfile] {
        var q = query
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let data = item as? Data else { throw SPAError.storage }
        do {
            let profiles = try JSONDecoder().decode([SavedProfile].self, from: data)
            guard profiles.count <= 16, Set(profiles.map(\.id)).count == profiles.count else { throw SPAError.storage }
            for row in profiles { _ = try Profile.parse(JSONEncoder().encode(row.profile)) }
            return profiles
        } catch { throw SPAError.storage }
    }
    static func save(_ profiles: [SavedProfile]) throws {
        guard profiles.count <= 16 else { throw SPAError.limit }
        let data = try JSONEncoder().encode(profiles)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            guard SecItemAdd(query.merging(attributes) { _, new in new } as CFDictionary, nil) == errSecSuccess else { throw SPAError.storage }
        } else if status != errSecSuccess { throw SPAError.storage }
    }
}
