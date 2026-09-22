// cybershield-android/app/src/main/cpp/yara_bridge.cpp
#include <jni.h>
#include <string>
#include <vector>
#include <yara.h>
#include <android/log.h>

#define LOG_TAG "YaraBridge"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Global YARA context
static YaraContext* g_yara_context = nullptr;

// Callback for YARA matches
static int yara_callback(
    YaraCallbackMessage callback_message,
    void* message_data,
    void* user_data
) {
    std::vector<std::string>* matches = (std::vector<std::string>*)user_data;

    if (callback_message == YARA_CALLBACK_MSG_RULE_MATCHING) {
        YaraCallbackMessageData* data = (YaraCallbackMessageData*)message_data;
        if (data && data->rule) {
            matches->push_back(std::string(data->rule->identifier));
        }
    }

    return YARA_CALLBACK_CONTINUE;
}

extern "C" {

// Initialize YARA engine
JNIEXPORT jboolean JNICALL
Java_com_cybershield_android_nativelib_YaraEngine_initYara(JNIEnv* env, jobject) {
    if (yr_initialize() == ERROR_SUCCESS) {
        LOGI("YARA initialized successfully");
        return JNI_TRUE;
    } else {
        LOGE("Failed to initialize YARA");
        return JNI_FALSE;
    }
}

// Cleanup YARA engine
JNIEXPORT void JNICALL
Java_com_cybershield_android_nativelib_YaraEngine_cleanupYara(JNIEnv* env, jobject) {
    yr_finalize();
    LOGI("YARA cleaned up");
}

// Compile YARA rules from file
JNIEXPORT jboolean JNICALL
Java_com_cybershield_android_nativelib_YaraEngine_compileRules(
    JNIEnv* env,
    jobject,
    jstring rulesPath
) {
    const char* path = env->GetStringUTFChars(rulesPath, nullptr);

    YaraRules* rules = nullptr;
    int result = yr_rules_create(path, &rules);

    env->ReleaseStringUTFChars(rulesPath, path);

    if (result == ERROR_SUCCESS) {
        LOGI("YARA rules compiled successfully: %s", path);
        return JNI_TRUE;
    } else {
        LOGE("Failed to compile YARA rules from: %s (error: %d)", path, result);
        return JNI_FALSE;
    }
}

// Scan file with YARA rules
JNIEXPORT jobjectArray JNICALL
Java_com_cybershield_android_nativelib_YaraEngine_scanFile(
    JNIEnv* env,
    jobject,
    jstring filePath,
    jstring rulesPath
) {
    const char* file_path = env->GetStringUTFChars(filePath, nullptr);
    const char* rules_path = env->GetStringUTFChars(rulesPath, nullptr);

    std::vector<std::string> matches;

    // Create and compile rules
    YaraRules* rules = nullptr;
    int result = yr_rules_create(rules_path, &rules);

    if (result != ERROR_SUCCESS) {
        LOGE("Failed to compile YARA rules: %d", result);
        env->ReleaseStringUTFChars(filePath, file_path);
        env->ReleaseStringUTFChars(rulesPath, rules_path);

        // Return empty array
        jobjectArray empty = env->NewObjectArray(0, env->FindClass("java/lang/String"), nullptr);
        return empty;
    }

    // Scan file
    result = yr_rules_scan_file(rules, file_path, 0, yara_callback, &matches, 0);

    if (result != ERROR_SUCCESS) {
        LOGW("YARA scan failed or timed out: %d", result);
    }

    // Create Java String array
    jclass stringClass = env->FindClass("java/lang/String");
    jobjectArray resultArray = env->NewObjectArray(matches.size(), stringClass, nullptr);

    for (size_t i = 0; i < matches.size(); ++i) {
        env->SetObjectArrayElement(
            resultArray,
            i,
            env->NewStringUTF(matches[i].c_str())
        );
    }

    // Cleanup
    yr_rules_destroy(rules);
    env->ReleaseStringUTFChars(filePath, file_path);
    env->ReleaseStringUTFChars(rulesPath, rules_path);

    LOGI("YARA scan complete - found %zu matches", matches.size());
    return resultArray;
}

// Scan buffer with YARA rules
JNIEXPORT jobjectArray JNICALL
Java_com_cybershield_android_nativelib_YaraEngine_scanBuffer(
    JNIEnv* env,
    jobject,
    jbyteArray buffer,
    jstring rulesPath
) {
    const char* rules_path = env->GetStringUTFChars(rulesPath, nullptr);
    jbyte* buffer_data = env->GetByteArrayElements(buffer, nullptr);
    jsize buffer_size = env->GetArrayLength(buffer);

    std::vector<std::string> matches;

    // Create and compile rules
    YaraRules* rules = nullptr;
    int result = yr_rules_create(rules_path, &rules);

    if (result != ERROR_SUCCESS) {
        LOGE("Failed to compile YARA rules: %d", result);
        env->ReleaseStringUTFChars(rulesPath, rules_path);
        env->ReleaseByteArrayElements(buffer, buffer_data, JNI_ABORT);

        // Return empty array
        jobjectArray empty = env->NewObjectArray(0, env->FindClass("java/lang/String"), nullptr);
        return empty;
    }

    // Scan buffer
    result = yr_rules_scan_buffer(
        rules,
        (uint8_t*)buffer_data,
        buffer_size,
        0,
        yara_callback,
        &matches,
        0
    );

    if (result != ERROR_SUCCESS && result != ERROR_INSUFFICIENT_MEMORY) {
        LOGE("YARA buffer scan failed: %d", result);
    }

    // Create Java String array
    jclass stringClass = env->FindClass("java/lang/String");
    jobjectArray resultArray = env->NewObjectArray(matches.size(), stringClass, nullptr);

    for (size_t i = 0; i < matches.size(); ++i) {
        env->SetObjectArrayElement(
            resultArray,
            i,
            env->NewStringUTF(matches[i].c_str())
        );
    }

    // Cleanup
    yr_rules_destroy(rules);
    env->ReleaseStringUTFChars(rulesPath, rules_path);
    env->ReleaseByteArrayElements(buffer, buffer_data, JNI_ABORT);

    LOGI("YARA buffer scan complete - found %zu matches", matches.size());
    return resultArray;
}

} // extern "C"
