// libadb.so - ADB pairing crypto (SPAKE2 + HKDF + AES-128-GCM), ringan.
// Nama kelas Java TIDAK di-hardcode: Java mengirimnya lewat system property
// "ino.adb.class" sebelum System.loadLibrary(); JNI_OnLoad membaca lalu RegisterNatives.
// Basis: Shizuku adb_pairing.cpp (Apache-2.0).
#include <jni.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <android/log.h>
#include <openssl/curve25519.h>
#include <openssl/hkdf.h>
#include <openssl/evp.h>
#include <openssl/aead.h>

#define TAG "InoAdb"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static const uint8_t kClientName[] = "adb pair client";
static const uint8_t kServerName[] = "adb pair server";
static constexpr size_t kHkdfKeyLength = 16;

struct Ctx {
    SPAKE2_CTX *spake;
    uint8_t msg[SPAKE2_MAX_MSG_SIZE];
    size_t msg_size;
    EVP_AEAD_CTX *aead;
    uint64_t dec_seq;
    uint64_t enc_seq;
};

static jlong nConstructor(JNIEnv *env, jclass, jboolean isClient, jbyteArray jPwd) {
    spake2_role_t role = isClient ? spake2_role_alice : spake2_role_bob;
    const uint8_t *my = isClient ? kClientName : kServerName;
    size_t myLen = isClient ? sizeof(kClientName) : sizeof(kServerName);
    const uint8_t *their = isClient ? kServerName : kClientName;
    size_t theirLen = isClient ? sizeof(kServerName) : sizeof(kClientName);

    SPAKE2_CTX *spake = SPAKE2_CTX_new(role, my, myLen, their, theirLen);
    if (!spake) { LOGE("SPAKE2_CTX_new"); return 0; }

    jsize n = env->GetArrayLength(jPwd);
    jbyte *pwd = env->GetByteArrayElements(jPwd, nullptr);
    Ctx *c = (Ctx *) calloc(1, sizeof(Ctx));
    if (!c || !pwd) {
        if (pwd) env->ReleaseByteArrayElements(jPwd, pwd, JNI_ABORT);
        free(c); SPAKE2_CTX_free(spake); return 0;
    }
    int ok = SPAKE2_generate_msg(spake, c->msg, &c->msg_size, sizeof(c->msg), (const uint8_t *) pwd, (size_t) n);
    env->ReleaseByteArrayElements(jPwd, pwd, JNI_ABORT);
    if (ok != 1 || c->msg_size == 0) {
        LOGE("SPAKE2_generate_msg");
        free(c); SPAKE2_CTX_free(spake); return 0;
    }
    c->spake = spake;
    return (jlong) c;
}

static jbyteArray nMsg(JNIEnv *env, jclass, jlong ptr) {
    Ctx *c = (Ctx *) ptr;
    if (!c) return nullptr;
    jbyteArray r = env->NewByteArray((jsize) c->msg_size);
    env->SetByteArrayRegion(r, 0, (jsize) c->msg_size, (const jbyte *) c->msg);
    return r;
}

static jboolean nInitCipher(JNIEnv *env, jclass, jlong ptr, jbyteArray jTheir) {
    Ctx *c = (Ctx *) ptr;
    if (!c || c->aead) return JNI_FALSE;
    jsize n = env->GetArrayLength(jTheir);
    if (n <= 0 || n > SPAKE2_MAX_MSG_SIZE) { LOGE("their msg size %d", (int) n); return JNI_FALSE; }

    jbyte *their = env->GetByteArrayElements(jTheir, nullptr);
    if (!their) return JNI_FALSE;
    uint8_t material[SPAKE2_MAX_KEY_SIZE];
    size_t materialLen = 0;
    int ok = SPAKE2_process_msg(c->spake, material, &materialLen, sizeof(material), (const uint8_t *) their, (size_t) n);
    env->ReleaseByteArrayElements(jTheir, their, JNI_ABORT);
    if (ok != 1) { LOGE("SPAKE2_process_msg"); return JNI_FALSE; }

    static const uint8_t info[] = "adb pairing_auth aes-128-gcm key";
    uint8_t key[kHkdfKeyLength];
    if (HKDF(key, sizeof(key), EVP_sha256(), material, materialLen, nullptr, 0, info, sizeof(info) - 1) != 1) {
        LOGE("HKDF"); return JNI_FALSE;
    }
    c->aead = EVP_AEAD_CTX_new(EVP_aead_aes_128_gcm(), key, sizeof(key), EVP_AEAD_DEFAULT_TAG_LENGTH);
    memset(key, 0, sizeof(key));
    memset(material, 0, sizeof(material));
    return c->aead ? JNI_TRUE : JNI_FALSE;
}

static jbyteArray crypt(JNIEnv *env, jlong ptr, jbyteArray jIn, bool seal) {
    Ctx *c = (Ctx *) ptr;
    if (!c || !c->aead) return nullptr;
    jsize inSize = env->GetArrayLength(jIn);
    jbyte *in = env->GetByteArrayElements(jIn, nullptr);
    if (!in) return nullptr;

    const EVP_AEAD *aead = EVP_AEAD_CTX_aead(c->aead);
    size_t nonceLen = EVP_AEAD_nonce_length(aead);
    uint8_t nonce[32] = {0};
    if (nonceLen > sizeof(nonce)) { env->ReleaseByteArrayElements(jIn, in, JNI_ABORT); return nullptr; }
    uint64_t seq = seal ? c->enc_seq : c->dec_seq;
    memcpy(nonce, &seq, sizeof(seq));

    size_t outCap = (size_t) inSize + EVP_AEAD_max_overhead(aead);
    uint8_t *out = (uint8_t *) malloc(outCap ? outCap : 1);
    size_t written = 0;
    int ok = 0;
    if (out) {
        ok = seal
             ? EVP_AEAD_CTX_seal(c->aead, out, &written, outCap, nonce, nonceLen, (const uint8_t *) in, (size_t) inSize, nullptr, 0)
             : EVP_AEAD_CTX_open(c->aead, out, &written, outCap, nonce, nonceLen, (const uint8_t *) in, (size_t) inSize, nullptr, 0);
    }
    env->ReleaseByteArrayElements(jIn, in, JNI_ABORT);

    jbyteArray r = nullptr;
    if (ok) {
        if (seal) ++c->enc_seq; else ++c->dec_seq;
        r = env->NewByteArray((jsize) written);
        env->SetByteArrayRegion(r, 0, (jsize) written, (const jbyte *) out);
    } else {
        LOGE("%s gagal (in=%d)", seal ? "encrypt" : "decrypt", (int) inSize);
    }
    free(out);
    return r;
}

static jbyteArray nEncrypt(JNIEnv *env, jclass, jlong ptr, jbyteArray in) { return crypt(env, ptr, in, true); }
static jbyteArray nDecrypt(JNIEnv *env, jclass, jlong ptr, jbyteArray in) { return crypt(env, ptr, in, false); }

static void nDestroy(JNIEnv *, jclass, jlong ptr) {
    Ctx *c = (Ctx *) ptr;
    if (!c) return;
    if (c->spake) SPAKE2_CTX_free(c->spake);
    if (c->aead) EVP_AEAD_CTX_free(c->aead);
    memset(c, 0, sizeof(*c));
    free(c);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) return -1;

    // Ambil nama kelas native dari System.getProperty("ino.adb.class")
    jclass sys = env->FindClass("java/lang/System");
    jmethodID gp = sys ? env->GetStaticMethodID(sys, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;") : nullptr;
    if (!gp) { env->ExceptionClear(); return -1; }
    jstring key = env->NewStringUTF("ino.adb.class");
    jstring val = (jstring) env->CallStaticObjectMethod(sys, gp, key);
    if (!val) { LOGE("property ino.adb.class belum di-set"); env->ExceptionClear(); return -1; }

    const char *name = env->GetStringUTFChars(val, nullptr);
    jclass cls = env->FindClass(name);
    env->ReleaseStringUTFChars(val, name);
    if (!cls) { env->ExceptionClear(); LOGE("kelas native tidak ditemukan"); return -1; }

    static const JNINativeMethod methods[] = {
            {"nativeConstructor", "(Z[B)J",  (void *) nConstructor},
            {"nativeMsg",         "(J)[B",   (void *) nMsg},
            {"nativeInitCipher",  "(J[B)Z",  (void *) nInitCipher},
            {"nativeEncrypt",     "(J[B)[B", (void *) nEncrypt},
            {"nativeDecrypt",     "(J[B)[B", (void *) nDecrypt},
            {"nativeDestroy",     "(J)V",    (void *) nDestroy},
    };
    if (env->RegisterNatives(cls, methods, sizeof(methods) / sizeof(methods[0])) < 0) {
        env->ExceptionClear(); LOGE("RegisterNatives gagal"); return -1;
    }
    return JNI_VERSION_1_6;
}
