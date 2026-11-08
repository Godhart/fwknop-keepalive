import SwiftUI
import UniformTypeIdentifiers

struct ImportDocument: Identifiable {
    let id = UUID()
    let data: Data
}

struct ContentView: View {
    @ObservedObject var model: AppModel
    @Environment(\.scenePhase) private var phase
    @State private var scanner = false
    @State private var picker = false
    @State private var document: ImportDocument?
    @State private var website: SavedProfile?
    @State private var deletion: SavedProfile?
    @State private var scanned: String?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("Отправка по таймеру работает только в открытом приложении. При уходе в браузер или блокировке экрана циклы останавливаются.")
                        .font(.footnote)
                    Button("Импортировать QR") { scanner = true }
                    Button("Импортировать JSON") { picker = true }
                    Button("Остановить все") { model.stopAll() }
                }
                ForEach(model.profiles) { row in
                    Section {
                        Text(row.profile.server + ":" + String(row.profile.spa_port))
                        Text(row.profile.access).font(.subheadline)
                        Text("Период: \(row.profile.interval_seconds) с. Запрос доступа: \(row.profile.access_timeout_seconds) с.")
                            .font(.caption)
                        Text(model.status[row.id] ?? "Остановлено").font(.caption).foregroundStyle(.secondary)
                        Button("Отправить SPA") { model.send(row.id) }
                            .disabled(!model.available || model.sending.contains(row.id))
                        Button(model.loops.contains(row.id) ? "Остановить цикл" : "Повторять, пока открыто") {
                            if model.loops.contains(row.id) { model.stop(row.id) } else { model.startLoop(row.id) }
                        }.disabled(!model.available)
                        Button("SPA → открыть сайт") {
                            guard let url = AppModel.websiteURL(row.website) else { return }
                            model.send(row.id) {
                                // SPA is unacknowledged. A short delay is only a convenience, not a server acknowledgement.
                                DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                                    guard model.available, model.profiles.contains(where: { $0.id == row.id }) else { return }
                                    UIApplication.shared.open(url)
                                }
                            }
                        }.disabled(row.website.isEmpty || !model.available || model.sending.contains(row.id))
                        Button(row.website.isEmpty ? "Указать сайт…" : "Изменить сайт…") { website = row }
                        Button("Удалить профиль", role: .destructive) { deletion = row }
                    } header: {
                        Text(row.profile.name + " · " + String(row.id.uuidString.prefix(8)))
                    }
                }
                if model.profiles.isEmpty {
                    Text("Профилей пока нет. Импортируйте существующий QR или JSON из Python-утилиты.")
                }
            }
            .navigationTitle("SPA Keepalive")
            .toolbar { Button("Перечитать") { model.reload() } }
        }
        .overlay {
            if phase != .active { Color(.systemBackground).ignoresSafeArea().overlay(Text("SPA Keepalive")) }
        }
        .sheet(isPresented: $scanner, onDismiss: {
            if let text = scanned { scanned = nil; document = ImportDocument(data: Data(text.utf8)) }
        }) {
            NavigationStack {
                Scanner(onResult: { text in scanned = text; scanner = false },
                        onError: { error in scanner = false; model.error = error })
                    .navigationTitle("Сканирование QR")
                    .toolbar { Button("Отмена") { scanner = false } }
            }
        }
        .fileImporter(isPresented: $picker, allowedContentTypes: [.json, .plainText], allowsMultipleSelection: false) { result in
            do {
                guard let url = try result.get().first else { return }
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                let file = try FileHandle(forReadingFrom: url); defer { try? file.close() }
                let data = try file.read(upToCount: 16385) ?? Data()
                guard data.count <= 16384 else { throw SPAError.invalid }
                document = ImportDocument(data: data)
            } catch { model.error = "Не удалось открыть JSON (максимум 16 KiB)." }
        }
        .sheet(item: $document) { doc in ImportView(data: doc.data, model: model) }
        .sheet(item: $website) { row in WebsiteView(row: row, model: model) }
        .alert("Ошибка", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK") { model.error = nil }
        } message: { Text(model.error ?? "") }
        .confirmationDialog("Удалить профиль?", isPresented: Binding(get: { deletion != nil }, set: { if !$0 { deletion = nil } }), titleVisibility: .visible) {
            Button("Удалить", role: .destructive) { if let row = deletion { model.remove(row.id) }; deletion = nil }
            Button("Отмена", role: .cancel) { deletion = nil }
        }
    }
}

struct ImportView: View {
    let data: Data
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var encrypted = false
    @State private var password = ""
    @State private var profile: Profile?
    @State private var error: String?
    @State private var busy = false
    @State private var closed = false
    var body: some View {
        NavigationStack {
            Form {
                if let profile {
                    Text(profile.name).font(.headline)
                    Text(profile.server + ":" + String(profile.spa_port))
                    Text(profile.access)
                    Text("Период: \(profile.interval_seconds) с; срок доступа: \(profile.access_timeout_seconds) с")
                    Text("IP: " + profile.allow_ip)
                    Button("Добавить профиль") {
                        do { try model.add(profile); dismiss() }
                        catch { self.error = error.localizedDescription }
                    }
                    Text("Импорт не отправляет SPA и не запускает цикл.").font(.footnote)
                } else if encrypted {
                    SecureField("Пароль профиля", text: $password)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Text("Пароль нужен только для импорта. Затем профиль хранится в Keychain этого устройства.")
                        .font(.footnote)
                    Button("Расшифровать") { unlock() }.disabled(password.isEmpty || busy)
                }
                if busy { ProgressView("Расшифровка…") }
                if let error { Text(error).foregroundStyle(.red) }
            }
            .navigationTitle("Импорт профиля")
            .toolbar { Button("Отмена") { password = ""; dismiss() } }
        }
        .onAppear {
            do {
                encrypted = try ProfileCrypto.isEncrypted(data)
                if !encrypted { profile = try Profile.parse(data) }
            } catch { self.error = SPAError.invalid.localizedDescription }
        }
        .onDisappear { closed = true; password = "" }
        .interactiveDismissDisabled(busy)
    }
    private func unlock() {
        let pass = password; let payload = data; password = ""; busy = true; error = nil
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try ProfileCrypto.unlock(payload, password: pass) }
            DispatchQueue.main.async {
                guard !closed else { return }; busy = false
                switch result {
                case .success(let p): profile = p
                case .failure: error = SPAError.password.localizedDescription
                }
            }
        }
    }
}

struct WebsiteView: View {
    let row: SavedProfile
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var error: String?
    var body: some View {
        NavigationStack {
            Form {
                TextField("https://service.example.org", text: $text)
                    .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                Text("Адрес сайта хранится локально и не меняет профиль QR. Разрешены HTTPS-адреса без логина и пароля. Пустое поле отключает кнопку открытия.")
                    .font(.footnote)
                Text("После открытия браузера циклы SPA остановятся. Доступ действует до таймаута сервера; при смене сети может понадобиться повторная отправка.")
                    .font(.footnote)
                if let error { Text(error).foregroundStyle(.red) }
                Button("Сохранить") {
                    do { try model.saveWebsite(row.id, text); dismiss() }
                    catch { self.error = "Укажите корректный HTTPS-адрес или оставьте поле пустым." }
                }
            }
            .navigationTitle("Сайт для профиля")
            .toolbar { Button("Отмена") { dismiss() } }
        }.onAppear { text = row.website }
    }
}
