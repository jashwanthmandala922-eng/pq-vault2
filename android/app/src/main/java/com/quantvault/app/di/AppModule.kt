package com.quantvault.app.di

import android.content.Context
import com.google.firebase.auth.FirebaseAuth
import com.quantvault.app.data.auth.FirebaseAuthManager
import com.quantvault.app.data.auth.MockAuthManager
import com.quantvault.app.data.local.NativeVault
import com.quantvault.app.data.local.SecurePreferences
import com.quantvault.app.data.repository.TOTPRepository
import com.quantvault.app.data.repository.VaultRepository
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideSecurePreferences(@ApplicationContext context: Context): SecurePreferences {
        return SecurePreferences(context)
    }

    @Provides
    @Singleton
    fun provideNativeVault(): NativeVault {
        return NativeVault.getInstance()
    }

    @Provides
    @Singleton
    fun provideVaultRepository(
        nativeVault: NativeVault,
        securePreferences: SecurePreferences
    ): VaultRepository {
        return VaultRepository(nativeVault, securePreferences)
    }

    @Provides
    @Singleton
    fun provideTOTPRepository(): TOTPRepository {
        return TOTPRepository()
    }

    @Provides
    @Singleton
    fun provideFirebaseAuthManager(@ApplicationContext context: Context): FirebaseAuthManager {
        return FirebaseAuthManager(context)
    }

    @Provides
    @Singleton
    fun provideFirebaseAuth(): FirebaseAuth {
        return FirebaseAuth.getInstance()
    }
}