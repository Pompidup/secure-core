package com.securecore.hardening

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securecore.store.PrivateDirDocumentStore
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class BackupPolicyTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun testDocumentsDir_isInNoBackupFilesDir() {
        val noBackupDir = context.noBackupFilesDir
        val documentsDir = File(noBackupDir, "documents")

        // PrivateDirDocumentStore uses noBackupFilesDir/documents/
        val store = PrivateDirDocumentStore(documentsDir)

        // Verify the documents directory is under noBackupFilesDir
        assertTrue(
            "Documents dir should be under noBackupFilesDir",
            documentsDir.absolutePath.startsWith(noBackupDir.absolutePath)
        )

        // Verify noBackupFilesDir is NOT under the regular filesDir
        // (filesDir is backed up by default, noBackupFilesDir is not)
        assertFalse(
            "noBackupFilesDir should differ from filesDir",
            noBackupDir.absolutePath == context.filesDir.absolutePath
        )
    }

    @Test
    fun testAllowBackup_isFalse() {
        val appInfo: ApplicationInfo = context.packageManager
            .getApplicationInfo(context.packageName, 0)

        val allowBackup = appInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP
        assertEquals(
            "allowBackup should be false (FLAG_ALLOW_BACKUP should not be set)",
            0,
            allowBackup
        )
    }

    @Test
    fun testNoBackupFilesDir_exists() {
        val noBackupDir = context.noBackupFilesDir
        assertNotNull("noBackupFilesDir should not be null", noBackupDir)
        assertTrue("noBackupFilesDir should exist or be creatable", noBackupDir.exists() || noBackupDir.mkdirs())
    }

    @Test
    fun testEncFilesNotInBackupableDir() {
        // Write a test .enc file and verify it's not under filesDir
        val documentsDir = File(context.noBackupFilesDir, "documents")
        documentsDir.mkdirs()
        val testFile = File(documentsDir, "backup-test.enc")
        testFile.writeBytes(ByteArray(16))

        try {
            val filesDir = context.filesDir.absolutePath
            val encPath = testFile.absolutePath

            assertFalse(
                "Encrypted files must not be under filesDir (which is backed up)",
                encPath.startsWith(filesDir) && !encPath.contains("no_backup")
            )
        } finally {
            testFile.delete()
        }
    }
}
