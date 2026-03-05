#if canImport(UIKit)
import Foundation
import UIKit

/// Observes app lifecycle events and purges preview files automatically.
///
/// - `willResignActive`: purges all preview files immediately.
/// - `willEnterForeground`: purges expired previews (older than 5 minutes).
public final class PreviewLifecycleObserver {
    private let previewManager: PreviewManagerProtocol
    private var observers: [NSObjectProtocol] = []

    public init(previewManager: PreviewManagerProtocol) {
        self.previewManager = previewManager

        observers.append(
            NotificationCenter.default.addObserver(
                forName: UIApplication.willResignActiveNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                self?.handleWillResignActive()
            }
        )

        observers.append(
            NotificationCenter.default.addObserver(
                forName: UIApplication.willEnterForegroundNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                self?.handleWillEnterForeground()
            }
        )
    }

    deinit {
        for observer in observers {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    private func handleWillResignActive() {
        _ = try? previewManager.purgeAllPreviews()
    }

    private func handleWillEnterForeground() {
        _ = try? previewManager.purgeExpiredPreviews(maxAge: 300)
    }
}
#endif
