package com.securecore.preview

import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner

class LifecyclePreviewPurger(
    private val previewManager: PreviewManager
) : DefaultLifecycleObserver {

    override fun onStart(owner: LifecycleOwner) {
        previewManager.purgeExpiredPreviews()
    }

    override fun onStop(owner: LifecycleOwner) {
        previewManager.purgeAllPreviews()
    }
}
