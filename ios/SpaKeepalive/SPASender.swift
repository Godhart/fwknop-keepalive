import Foundation
import Network

/// All methods/callbacks run on main; libfko's global random state is serialized.
final class SPASender {
    static func packet(_ profile: Profile) throws -> Data {
        let key = try canonicalBase64(profile.key_base64, range: 16...32)
        let hmac = try canonicalBase64(profile.hmac_key_base64, range: 32...64)
        var output: UnsafeMutablePointer<CChar>?
        let rc = profile.message.withCString { message in
            profile.username.withCString { username in
                key.withUnsafeBytes { k in
                    hmac.withUnsafeBytes { h in
                        spa_packet(message, username, Int32(profile.access_timeout_seconds),
                            k.baseAddress!.assumingMemoryBound(to: UInt8.self), Int32(key.count),
                            h.baseAddress!.assumingMemoryBound(to: UInt8.self), Int32(hmac.count), &output)
                    }
                }
            }
        }
        defer { free(output) }
        guard rc == 0, let output else { throw SPAError.network }
        return Data(String(cString: output).utf8)
    }
    private var connection: NWConnection?
    private var timeout: DispatchWorkItem?
    private var completed = false
    private var completion: ((Result<Void, Error>) -> Void)?
    func start(_ profile: Profile, completion: @escaping (Result<Void, Error>) -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        self.completion = completion
        do {
            let packet = try Self.packet(profile)
            let parameters = NWParameters.udp
            (parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options)?.version = .v4
            let connection = NWConnection(host: NWEndpoint.Host(profile.server),
                port: NWEndpoint.Port(rawValue: UInt16(profile.spa_port))!, using: parameters)
            self.connection = connection
            var sent = false
            connection.stateUpdateHandler = { [weak self] state in
                guard let self, !self.completed else { return }
                switch state {
                case .ready:
                    guard !sent else { return }; sent = true
                    connection.send(content: packet, completion: .contentProcessed { [weak self] error in
                        if let error { self?.finish(.failure(error)) }
                        else { self?.finish(Result<Void, Error>(catching: {})) }
                    })
                case .failed: self.finish(.failure(SPAError.network))
                default: break
                }
            }
            let deadline = DispatchWorkItem { [weak self] in self?.finish(.failure(SPAError.network)) }
            timeout = deadline
            DispatchQueue.main.asyncAfter(deadline: .now() + 15, execute: deadline)
            connection.start(queue: .main)
        } catch { finish(.failure(error)) }
    }
    func cancel() { finish(.failure(SPAError.inactive)) }
    private func finish(_ result: Result<Void, Error>) {
        guard !completed else { return }; completed = true
        timeout?.cancel(); timeout = nil
        connection?.stateUpdateHandler = nil; connection?.cancel(); connection = nil
        let callback = completion; completion = nil; callback?(result)
    }
}
