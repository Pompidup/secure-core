import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Manages a time-limited session after successful biometric/passcode authentication.
///
/// The session expires after `sessionDuration` seconds or when the app moves to the background.
public final class SessionManager {
    public static let defaultSessionDuration: TimeInterval = 300 // 5 minutes

    private let sessionDuration: TimeInterval
    private var lastAuthDate: Date?
    private let clock: () -> Date

    #if canImport(UIKit)
    private var backgroundObserver: NSObjectProtocol?
    #endif

    public init(
        sessionDuration: TimeInterval = SessionManager.defaultSessionDuration,
        clock: @escaping () -> Date = { Date() }
    ) {
        self.sessionDuration = sessionDuration
        self.clock = clock

        #if canImport(UIKit)
        backgroundObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.willResignActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.invalidateSession()
        }
        #endif
    }

    deinit {
        #if canImport(UIKit)
        if let observer = backgroundObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        #endif
    }

    /// Returns `true` if a successful authentication occurred within the session window.
    public func isSessionActive() -> Bool {
        guard let lastAuth = lastAuthDate else {
            return false
        }
        return clock().timeIntervalSince(lastAuth) < sessionDuration
    }

    /// Records a successful authentication, starting or extending the session.
    public func recordSuccessfulAuth() {
        lastAuthDate = clock()
    }

    /// Immediately ends the current session.
    public func invalidateSession() {
        lastAuthDate = nil
    }
}
