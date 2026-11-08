import SwiftUI
import AVFoundation

struct Scanner: UIViewControllerRepresentable {
    var onResult: (String) -> Void
    var onError: (String) -> Void
    func makeUIViewController(context: Context) -> ScannerController {
        let vc = ScannerController(); vc.onResult = onResult; vc.onError = onError; return vc
    }
    func updateUIViewController(_ controller: ScannerController, context: Context) {}
    static func dismantleUIViewController(_ controller: ScannerController, coordinator: ()) { controller.stop() }
}

final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onResult: ((String) -> Void)?
    var onError: ((String) -> Void)?
    private let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "spa.camera")
    private var preview: AVCaptureVideoPreviewLayer?
    private var runningView = false
    private var delivered = false
    override func viewDidLoad() {
        super.viewDidLoad(); view.backgroundColor = .black
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill; view.layer.addSublayer(layer); preview = layer
    }
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated); runningView = true
        AVCaptureDevice.requestAccess(for: .video) { [weak self] allowed in
            DispatchQueue.main.async {
                guard let self, self.runningView else { return }
                guard allowed else { self.onError?("Разрешите камеру в настройках iOS или импортируйте JSON."); return }
                self.configure()
            }
        }
    }
    private func configure() {
        queue.async { [weak self] in
            guard let self else { return }
            do {
                if self.session.inputs.isEmpty {
                    guard let camera = AVCaptureDevice.default(for: .video) else { throw SPAError.invalid }
                    let input = try AVCaptureDeviceInput(device: camera)
                    let output = AVCaptureMetadataOutput()
                    self.session.beginConfiguration()
                    guard self.session.canAddInput(input), self.session.canAddOutput(output) else {
                        self.session.commitConfiguration(); throw SPAError.invalid
                    }
                    self.session.addInput(input); self.session.addOutput(output)
                    output.setMetadataObjectsDelegate(self, queue: .main)
                    guard output.availableMetadataObjectTypes.contains(.qr) else {
                        self.session.commitConfiguration(); throw SPAError.invalid
                    }
                    output.metadataObjectTypes = [.qr]
                    self.session.commitConfiguration()
                }
                self.session.startRunning()
            } catch {
                DispatchQueue.main.async { [weak self] in self?.onError?("Камера недоступна. Используйте импорт JSON.") }
            }
        }
    }
    override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); preview?.frame = view.bounds }
    override func viewDidDisappear(_ animated: Bool) { super.viewDidDisappear(animated); stop() }
    func stop() {
        runningView = false
        queue.async { [weak self] in self?.session.stopRunning() }
    }
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard runningView, !delivered,
              let text = (objects.first as? AVMetadataMachineReadableCodeObject)?.stringValue else { return }
        delivered = true; stop(); onResult?(text)
    }
}
