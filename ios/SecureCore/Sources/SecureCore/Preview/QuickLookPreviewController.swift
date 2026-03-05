#if canImport(UIKit) && canImport(QuickLook)
import QuickLook
import UIKit

/// UIKit wrapper that presents a `QLPreviewController` for a temporary preview file
/// and releases the preview handle on dismissal.
public final class QuickLookPreviewController: NSObject, QLPreviewControllerDataSource,
    QLPreviewControllerDelegate
{
    private let fileURL: URL
    private let previewManager: PreviewManagerProtocol
    private let handle: PreviewHandle

    /// Creates a controller for a `.tempFile` preview handle.
    /// - Parameters:
    ///   - handle: Must be a `.tempFile` handle.
    ///   - previewManager: Used to release the handle on dismissal.
    public init?(handle: PreviewHandle, previewManager: PreviewManagerProtocol) {
        guard case .tempFile(let url, _) = handle else { return nil }
        self.fileURL = url
        self.previewManager = previewManager
        self.handle = handle
        super.init()
    }

    /// Presents the QuickLook preview from the given view controller.
    public func present(from viewController: UIViewController, animated: Bool = true) {
        let qlController = QLPreviewController()
        qlController.dataSource = self
        qlController.delegate = self
        viewController.present(qlController, animated: animated)
    }

    // MARK: - QLPreviewControllerDataSource

    public func numberOfPreviewItems(in controller: QLPreviewController) -> Int {
        1
    }

    public func previewController(
        _ controller: QLPreviewController, previewItemAt index: Int
    ) -> QLPreviewItem {
        fileURL as QLPreviewItem
    }

    // MARK: - QLPreviewControllerDelegate

    public func previewControllerDidDismiss(_ controller: QLPreviewController) {
        try? previewManager.releasePreview(handle)
    }
}
#endif
