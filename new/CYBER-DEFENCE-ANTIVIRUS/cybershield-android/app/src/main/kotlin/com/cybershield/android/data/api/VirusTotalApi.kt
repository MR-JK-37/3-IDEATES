// cybershield-android/app/src/main/kotlin/com/cybershield/android/data/api/VirusTotalApi.kt
package com.cybershield.android.data.api

import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.Path
import com.google.gson.annotations.SerializedName

interface VirusTotalApi {
    @GET("files/{file_hash}")
    suspend fun getFileAnalysis(
        @Path("file_hash") fileHash: String,
        @Header("x-apikey") apiKey: String
    ): VirusTotalResponse
}

data class VirusTotalResponse(
    @SerializedName("data")
    val data: FileAnalysis?
)

data class FileAnalysis(
    @SerializedName("id")
    val id: String,
    @SerializedName("type")
    val type: String,
    @SerializedName("attributes")
    val attributes: FileAttributes
)

data class FileAttributes(
    @SerializedName("meaningful_name")
    val meaningfulName: String?,
    @SerializedName("size")
    val size: Long?,
    @SerializedName("type_description")
    val typeDescription: String?,
    @SerializedName("last_analysis_stats")
    val lastAnalysisStats: LastAnalysisStats?,
    @SerializedName("last_analysis_date")
    val lastAnalysisDate: Long?
)

data class LastAnalysisStats(
    @SerializedName("malicious")
    val malicious: Int = 0,
    @SerializedName("suspicious")
    val suspicious: Int = 0,
    @SerializedName("undetected")
    val undetected: Int = 0,
    @SerializedName("harmless")
    val harmless: Int = 0
)

// URL Scanning API
interface VirusTotalUrlApi {
    @GET("urls/{url_id}")
    suspend fun getUrlAnalysis(
        @Path("url_id") urlId: String,
        @Header("x-apikey") apiKey: String
    ): VirusTotalUrlResponse
}

data class VirusTotalUrlResponse(
    @SerializedName("data")
    val data: UrlAnalysis?
)

data class UrlAnalysis(
    @SerializedName("id")
    val id: String,
    @SerializedName("attributes")
    val attributes: UrlAttributes
)

data class UrlAttributes(
    @SerializedName("url")
    val url: String,
    @SerializedName("last_analysis_stats")
    val lastAnalysisStats: LastAnalysisStats?,
    @SerializedName("last_http_response_code")
    val lastHttpResponseCode: Int?,
    @SerializedName("last_analysis_date")
    val lastAnalysisDate: Long?
)
