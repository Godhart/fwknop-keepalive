import Foundation
import CoreFoundation

enum SPAError: LocalizedError {
    case invalid, password, storage, network, limit, inactive
    var errorDescription: String? {
        switch self {
        case .invalid: return "Некорректный или неподдерживаемый профиль."
        case .password: return "Неверный пароль или повреждённый профиль."
        case .storage: return "Не удалось прочитать или сохранить профили в Keychain."
        case .network: return "Ошибка отправки или истёк таймаут. Приём сервером не подтверждён."
        case .limit: return "Можно сохранить не более 16 профилей."
        case .inactive: return "Отправка доступна, пока приложение открыто."
        }
    }
}

/// Wire profiles are flat objects. Reject duplicate keys, nesting and non-JSON syntax.
enum FlatJSON {
    static func parse(_ data: Data) throws -> [String: Any] {
        guard data.count <= 16384 else { throw SPAError.invalid }
        let bytes = Array(data); var i = 0; var result: [String: Any] = [:]
        func space() { while i < bytes.count && [9,10,13,32].contains(bytes[i]) { i += 1 } }
        func string() throws -> String {
            guard i < bytes.count, bytes[i] == 34 else { throw SPAError.invalid }
            let start = i; i += 1
            while i < bytes.count {
                if bytes[i] == 92 { i += 2; continue }
                if bytes[i] == 34 {
                    i += 1
                    guard let s = try JSONSerialization.jsonObject(with: Data(bytes[start..<i]), options: .fragmentsAllowed) as? String else { throw SPAError.invalid }
                    return s
                }
                i += 1
            }
            throw SPAError.invalid
        }
        space(); guard i < bytes.count, bytes[i] == 123 else { throw SPAError.invalid }; i += 1
        space()
        if i < bytes.count && bytes[i] == 125 { i += 1 }
        else {
            while true {
                space(); let key = try string()
                guard result[key] == nil else { throw SPAError.invalid }
                space(); guard i < bytes.count, bytes[i] == 58 else { throw SPAError.invalid }; i += 1; space()
                guard i < bytes.count else { throw SPAError.invalid }
                if bytes[i] == 34 { result[key] = try string() }
                else {
                    let start = i
                    while i < bytes.count && bytes[i] >= 48 && bytes[i] <= 57 { i += 1 }
                    guard i > start, !(i-start > 1 && bytes[start] == 48),
                          let n = Int(String(decoding: bytes[start..<i], as: UTF8.self)) else { throw SPAError.invalid }
                    result[key] = n
                }
                space(); guard i < bytes.count else { throw SPAError.invalid }
                if bytes[i] == 125 { i += 1; break }
                guard bytes[i] == 44 else { throw SPAError.invalid }; i += 1
            }
        }
        space(); guard i == bytes.count else { throw SPAError.invalid }
        return result
    }
}

struct Profile: Codable, Equatable {
    let version: Int
    let name, server: String
    let spa_port: Int
    let access, allow_ip, username: String
    let interval_seconds, access_timeout_seconds: Int
    let key_base64, hmac_key_base64: String

    static func parse(_ data: Data) throws -> Profile {
        let values = try FlatJSON.parse(data)
        let schemaURL = Bundle.main.url(forResource: "profile.schema", withExtension: "json")!
        let schema = try JSONSerialization.jsonObject(with: Data(contentsOf: schemaURL)) as! [String: Any]
        let properties = schema["properties"] as! [String: [String: Any]]
        guard Set(values.keys) == Set(properties.keys) else { throw SPAError.invalid }
        for (key, rule) in properties {
            if rule["type"] as? String == "integer" {
                guard let n = values[key] as? Int else { throw SPAError.invalid }
                if let exact = rule["const"] as? Int, n != exact { throw SPAError.invalid }
                if n < (rule["minimum"] as? Int ?? Int.min) || n > (rule["maximum"] as? Int ?? Int.max) { throw SPAError.invalid }
            } else {
                guard let s = values[key] as? String else { throw SPAError.invalid }
                let count = s.unicodeScalars.count
                guard count >= (rule["minLength"] as? Int ?? 0), count <= (rule["maxLength"] as? Int ?? Int.max) else { throw SPAError.invalid }
                if let pattern = rule["pattern"] as? String,
                   s.range(of: pattern, options: .regularExpression) == nil { throw SPAError.invalid }
            }
        }
        let p = try JSONDecoder().decode(Profile.self, from: data)
        guard p.interval_seconds < p.access_timeout_seconds,
              p.key_base64 != p.hmac_key_base64 else { throw SPAError.invalid }
        _ = try canonicalBase64(p.key_base64, range: 16...32)
        _ = try canonicalBase64(p.hmac_key_base64, range: 32...64)
        for pair in p.access.split(separator: ",") {
            guard let port = Int(pair.split(separator: "/")[1]), (1...65535).contains(port) else { throw SPAError.invalid }
        }
        if p.allow_ip != "source" {
            let parts = p.allow_ip.split(separator: ".")
            guard parts.count == 4 else { throw SPAError.invalid }
            var address: UInt32 = 0
            for part in parts {
                guard let n = UInt8(part), String(n) == part else { throw SPAError.invalid }
                address = address << 8 | UInt32(n)
            }
            guard address != 0, address != UInt32.max, address >> 28 != 14 else { throw SPAError.invalid }
        }
        return p
    }
    var message: String { "\(allow_ip == "source" ? "0.0.0.0" : allow_ip),\(access)" }
}

func canonicalBase64(_ text: String, range: ClosedRange<Int>) throws -> Data {
    guard let bytes = Data(base64Encoded: text), bytes.base64EncodedString() == text,
          range.contains(bytes.count) else { throw SPAError.invalid }
    return bytes
}

struct SavedProfile: Codable, Identifiable {
    var id = UUID()
    let profile: Profile
    var website = ""
}
