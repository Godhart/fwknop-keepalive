import Foundation
import SwiftUI

final class AppModel: ObservableObject {
    @Published private(set) var profiles: [SavedProfile] = []
    @Published private(set) var loops: Set<UUID> = []
    @Published private(set) var status: [UUID: String] = [:]
    @Published private(set) var sending: Set<UUID> = []
    @Published private(set) var available = false
    @Published var error: String?
    private var storageReady = false
    private var jobs: [UUID: SPASender] = [:]
    private var timers: [UUID: DispatchWorkItem] = [:]

    private let loadProfiles: () throws -> [SavedProfile]
    private let saveProfiles: ([SavedProfile]) throws -> Void
    init(load: @escaping () throws -> [SavedProfile] = ProfileStore.load,
         save: @escaping ([SavedProfile]) throws -> Void = ProfileStore.save) {
        loadProfiles = load; saveProfiles = save; reload()
    }
    func reload() {
        do { profiles = try loadProfiles(); storageReady = true; error = nil }
        catch { storageReady = false; self.error = error.localizedDescription }
    }
    func setActive(_ active: Bool) {
        available = active
        if !active { stopAll() }
    }
    func add(_ profile: Profile) throws {
        guard storageReady else { throw SPAError.storage }
        guard profiles.count < 16 else { throw SPAError.limit }
        var updated = profiles; updated.append(SavedProfile(profile: profile))
        try saveProfiles(updated); profiles = updated
    }
    func remove(_ id: UUID) {
        do {
            guard storageReady else { throw SPAError.storage }
            let updated = profiles.filter { $0.id != id }
            try saveProfiles(updated); stop(id); profiles = updated
            status[id] = nil
        } catch { self.error = error.localizedDescription }
    }
    static func websiteURL(_ value: String) -> URL? {
        guard let c = URLComponents(string: value), c.scheme?.lowercased() == "https",
              c.host?.isEmpty == false, c.user == nil, c.password == nil else { return nil }
        return c.url
    }
    func saveWebsite(_ id: UUID, _ value: String) throws {
        let value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.isEmpty || Self.websiteURL(value) != nil else { throw SPAError.invalid }
        guard storageReady, let index = profiles.firstIndex(where: { $0.id == id }) else { throw SPAError.storage }
        var updated = profiles; updated[index].website = value
        try saveProfiles(updated); profiles = updated
    }
    func startLoop(_ id: UUID) {
        guard available else { return }
        loops.insert(id); send(id)
    }
    func stop(_ id: UUID) {
        loops.remove(id); timers.removeValue(forKey: id)?.cancel()
        jobs.removeValue(forKey: id)?.cancel()
        sending.remove(id); status[id] = "Остановлено"
    }
    func stopAll() {
        for id in Set(loops).union(jobs.keys).union(timers.keys) { stop(id) }
    }
    func send(_ id: UUID, then: (() -> Void)? = nil) {
        guard available, !sending.contains(id),
              let row = profiles.first(where: { $0.id == id }) else { return }
        timers.removeValue(forKey: id)?.cancel()
        let sender = SPASender(); jobs[id] = sender; sending.insert(id)
        status[id] = "Отправка…"
        sender.start(row.profile) { [weak self, weak sender] result in
            guard let self, let sender, self.jobs[id] === sender else { return }
            self.jobs[id] = nil; self.sending.remove(id)
            guard self.available else { return }
            switch result {
            case .success:
                self.status[id] = "UDP передан системе в \(Date().formatted(date: .omitted, time: .standard)). Приём не подтверждён."
                then?()
            case .failure:
                self.status[id] = SPAError.network.localizedDescription
            }
            if self.loops.contains(id) && self.available {
                let timer = DispatchWorkItem { [weak self] in self?.send(id) }
                self.timers[id] = timer
                DispatchQueue.main.asyncAfter(deadline: .now() + Double(row.profile.interval_seconds), execute: timer)
            }
        }
    }
}
