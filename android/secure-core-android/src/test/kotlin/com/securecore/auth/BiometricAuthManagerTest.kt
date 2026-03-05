package com.securecore.auth

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class BiometricAuthManagerTest {

    private var currentTime = 1_000_000L
    private lateinit var authManager: BiometricAuthManager

    @Before
    fun setUp() {
        authManager = BiometricAuthManager(
            sessionDurationMs = 5 * 60 * 1000L,
            clock = { currentTime }
        )
    }

    @Test
    fun testSessionInactive_byDefault() {
        assertFalse(authManager.isSessionActive())
        assertEquals(0L, authManager.getSessionRemainingMs())
    }

    @Test
    fun testSessionValid_afterAuth() {
        // Simulate a successful auth by directly setting the session
        simulateSuccessfulAuth()

        assertTrue(authManager.isSessionActive())
        assertEquals(5 * 60 * 1000L, authManager.getSessionRemainingMs())
    }

    @Test
    fun testSessionExpired_after5min() {
        simulateSuccessfulAuth()
        assertTrue(authManager.isSessionActive())

        // Advance clock by 5 minutes + 1ms
        currentTime += 5 * 60 * 1000L + 1

        assertFalse(authManager.isSessionActive())
        assertEquals(0L, authManager.getSessionRemainingMs())
    }

    @Test
    fun testSessionStillValid_at4min59s() {
        simulateSuccessfulAuth()

        // Advance clock by 4 minutes 59 seconds
        currentTime += 4 * 60 * 1000L + 59 * 1000L

        assertTrue(authManager.isSessionActive())
        assertTrue(authManager.getSessionRemainingMs() > 0)
    }

    @Test
    fun testInvalidateSession_clearsAuth() {
        simulateSuccessfulAuth()
        assertTrue(authManager.isSessionActive())

        authManager.invalidateSession()

        assertFalse(authManager.isSessionActive())
        assertEquals(0L, authManager.getSessionRemainingMs())
    }

    @Test
    fun testGetSessionRemainingMs_decreases() {
        simulateSuccessfulAuth()

        assertEquals(5 * 60 * 1000L, authManager.getSessionRemainingMs())

        currentTime += 60 * 1000L // +1 minute
        assertEquals(4 * 60 * 1000L, authManager.getSessionRemainingMs())

        currentTime += 3 * 60 * 1000L // +3 more minutes
        assertEquals(1 * 60 * 1000L, authManager.getSessionRemainingMs())
    }

    @Test
    fun testCustomSessionDuration() {
        authManager = BiometricAuthManager(
            sessionDurationMs = 30_000L, // 30 seconds
            clock = { currentTime }
        )
        simulateSuccessfulAuth()

        assertTrue(authManager.isSessionActive())

        currentTime += 30_001L
        assertFalse(authManager.isSessionActive())
    }

    /**
     * Simulates a successful authentication by using reflection to set lastAuthAt.
     * In real usage, this is set by BiometricPrompt callback.
     */
    private fun simulateSuccessfulAuth() {
        val field = BiometricAuthManager::class.java.getDeclaredField("lastAuthAt")
        field.isAccessible = true
        field.setLong(authManager, currentTime)
    }
}
