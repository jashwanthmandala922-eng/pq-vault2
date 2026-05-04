package com.quantvault.app.data.auth

import com.google.firebase.auth.FirebaseUser
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class MockAuthManager @Inject constructor() {
    private var mockUser: FirebaseUser? = null

    fun isSignedIn(): Boolean = mockUser != null

    fun getCurrentUser(): FirebaseUser? = mockUser

    fun getAccessToken(): String = "mock_access_token_${System.currentTimeMillis()}"

    suspend fun signIn(): Result<FirebaseUser> {
        return Result.failure(NotImplementedError("Use FirebaseAuthManager"))
    }

    suspend fun signOut() {
        mockUser = null
    }
}