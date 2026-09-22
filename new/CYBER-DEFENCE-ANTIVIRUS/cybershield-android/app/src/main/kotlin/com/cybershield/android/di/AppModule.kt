// cybershield-android/app/src/main/kotlin/com/cybershield/android/di/AppModule.kt
package com.cybershield.android.di

import android.content.Context
import com.cybershield.android.data.api.VirusTotalApi
import com.cybershield.android.data.api.VirusTotalUrlApi
import com.cybershield.android.data.db.CyberShieldDatabase
import com.cybershield.android.data.repository.ThreatRepository
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): CyberShieldDatabase {
        return CyberShieldDatabase.getDatabase(context)
    }

    @Provides
    @Singleton
    fun provideThreatDao(database: CyberShieldDatabase) = database.threatDao()

    @Provides
    @Singleton
    fun provideScanResultDao(database: CyberShieldDatabase) = database.scanResultDao()

    @Provides
    @Singleton
    fun provideUrlScanDao(database: CyberShieldDatabase) = database.urlScanDao()

    @Provides
    @Singleton
    fun provideGson(): Gson {
        return GsonBuilder()
            .setLenient()
            .create()
    }

    @Provides
    @Singleton
    fun provideOkHttpClient(): OkHttpClient {
        return OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build()
    }

    @Provides
    @Singleton
    fun provideVirusTotalRetrofit(okHttpClient: OkHttpClient, gson: Gson): Retrofit {
        return Retrofit.Builder()
            .baseUrl("https://www.virustotal.com/api/v3/")
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create(gson))
            .build()
    }

    @Provides
    @Singleton
    fun provideVirusTotalApi(retrofit: Retrofit): VirusTotalApi {
        return retrofit.create(VirusTotalApi::class.java)
    }

    @Provides
    @Singleton
    fun provideVirusTotalUrlApi(retrofit: Retrofit): VirusTotalUrlApi {
        return retrofit.create(VirusTotalUrlApi::class.java)
    }

    @Provides
    @Singleton
    fun provideVirusTotalApiKey(): String {
        // In production, load from secure storage or BuildConfig
        return System.getenv("VIRUSTOTAL_API_KEY") ?: ""
    }

    @Provides
    @Singleton
    fun provideThreatRepository(
        threatDao: com.cybershield.android.data.dao.ThreatDao,
        scanResultDao: com.cybershield.android.data.dao.ScanResultDao,
        urlScanDao: com.cybershield.android.data.dao.UrlScanDao,
        virusTotalApi: VirusTotalApi,
        virusTotalUrlApi: VirusTotalUrlApi,
        @Provides.VT_API_KEY apiKey: String
    ): ThreatRepository {
        return ThreatRepository(
            threatDao = threatDao,
            scanResultDao = scanResultDao,
            urlScanDao = urlScanDao,
            virusTotalApi = virusTotalApi,
            virusTotalUrlApi = virusTotalUrlApi,
            apiKey = apiKey
        )
    }
}

// Qualifier for API key
annotation class VT_API_KEY
