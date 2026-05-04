package com.quantvault.app.security

import android.content.Context
import com.google.android.gms.common.api.GoogleApiClient
import com.google.android.gms.common.api.GoogleApiClient.Builder
import com.google.android.gms.common.api.GoogleApiClient.ConnectionCallbacks
import com.google.android.gms.common.api.GoogleApiClient.OnConnectionFailedListener
import com.google.android.gms.safetynet.SafetyNet
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object SecurityModule {

    @Provides
    @Singleton
    fun provideTamperDetector(
        @ApplicationContext context: Context
    ): TamperDetector {
        return TamperDetector(context)
    }

    @Provides
    @Singleton
    fun provideGoogleApiClient(
        @ApplicationContext context: Context
    ): GoogleApiClient {
        return Builder(context)
            .addApi(SafetyNet.API)
            .build()
    }
}