import SwiftUI

@main
struct SpaKeepaliveApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var phase
    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
                .onAppear { model.setActive(phase == .active) }
                .onChange(of: phase) { value in model.setActive(value == .active) }
        }
    }
}
