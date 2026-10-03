#include "module.hpp"

#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include "binder.hpp"
#include "zygisk.hpp"

#define ARR_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define STR_LEN(a) (ARR_LEN(a) - 1)
#define VENDING_PROC "com.android.vending"

#define PM_DESC u"android.content.pm.IPackageManager"

static char* DETACH_TXT = nullptr;
static size_t HEADERS_LEN = 0;
static uint32_t getApplicationEnabledSetting_code = 0;

#ifndef DETACH_DEBUG
#define DETACH_DEBUG 1
#endif

#if DETACH_DEBUG
static int dbg_calls = 0;       // total hook invocations
static int dbg_raw_budget = 40; // raw parcel dumps (any descriptor)
static int dbg_pm_budget = 300; // IPackageManager transactions

static void dbg_u16_to_ascii(const char16_t* s, uint32_t len, char* out, size_t outsz) {
    size_t n = len < outsz - 1 ? len : outsz - 1;
    for (size_t i = 0; i < n; i++) out[i] = s[i] < 128 && s[i] >= 32 ? (char)s[i] : '?';
    out[n] = 0;
}
#endif

static inline void detach(PParcel* pparcel, uint32_t code) {
    if (pparcel == nullptr || pparcel->data == nullptr) return;
    size_t dsz = pparcel->data_size;

#if DETACH_DEBUG
    dbg_calls++;
    if (dbg_calls == 1 || dbg_calls == 100 || dbg_calls == 1000 || dbg_calls == 10000) {
        LOGD("hook alive: calls=%d", dbg_calls);
    }
    if (dbg_raw_budget > 0) {
        dbg_raw_budget--;
        uint32_t w[16] = {0};
        size_t n = dsz < sizeof(w) ? dsz : sizeof(w);
        memcpy(w, pparcel->data, n);
        LOGD("raw code=%u size=%zu err=%zu hdr=%zu: %08x %08x %08x %08x %08x %08x %08x %08x", code, dsz,
             pparcel->error, HEADERS_LEN, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
    }
#endif

    if (dsz < HEADERS_LEN + 4) return;
    auto parcel = FakeParcel(pparcel->data);
    parcel.skip(HEADERS_LEN);  // header

    auto descLen = parcel.readInt32();
    if (descLen != STR_LEN(PM_DESC)) return;
    // header + len + desc(+null, padded to 4) + 2nd len must fit
    if (dsz < HEADERS_LEN + 4 + (descLen + 1) * sizeof(char16_t) + 2 + 4) return;
    auto desc = parcel.readString16(descLen);
    if (memcmp(desc, PM_DESC, descLen * sizeof(char16_t)) != 0) return;

#if DETACH_DEBUG
    if (dbg_pm_budget > 0) {
        dbg_pm_budget--;
        LOGD("IPackageManager transaction code=%u (want %u) size=%zu", code, getApplicationEnabledSetting_code, dsz);
    }
#endif

    if (code != getApplicationEnabledSetting_code) return;
    parcel.skip(2);

    size_t cur = parcel.getCursor();
    if (dsz < cur + 4) return;
    auto pkgLen = parcel.readInt32();
    if (pkgLen == 0 || pkgLen > 255 || dsz < cur + 4 + (pkgLen + 1) * sizeof(char16_t)) return;
    auto pkg = parcel.readString16(pkgLen);

#if DETACH_DEBUG
    {
        char buf[128];
        dbg_u16_to_ascii(pkg, pkgLen, buf, sizeof(buf));
        LOGD("getApplicationEnabledSetting pkg='%s' len=%u", buf, pkgLen);
    }
#endif

    auto pkgLenB = (uint8_t)(pkgLen * 2 - 1);
    size_t i = 0;
    uint8_t dlen;
    while ((dlen = DETACH_TXT[i])) {
        const char* dptr = DETACH_TXT + i + sizeof(dlen);
        i += sizeof(dlen) + dlen;
        if (dlen != pkgLenB) continue;
        if (memcmp(dptr, pkg, dlen) == 0) {
#if DETACH_DEBUG
            LOGD("DETACHED a package");
#endif
            *pkg = 0;
            return;
        }
    }
}

int (*transact_orig)(void*, int32_t, uint32_t, void*, void*, uint32_t);

int transact_hook(void* self, int32_t handle, uint32_t code, void* pdata, void* preply, uint32_t flags) {
    auto parcel = (PParcel*)pdata;
    detach(parcel, code);
    return transact_orig(self, handle, code, pdata, preply, flags);
}


// zygisk's pltHook can silently do nothing on some setups: verify the GOT slot ourselves and patch it if needed.
static bool ensureHooked(const char* sym) {
    uintptr_t base = 0;
    ino_t inode = 0;
    dev_t dev = 0;
    char path[160] = "";
    if (!findLibBase("libbinder.so", &base, &inode, &dev, path, sizeof(path))) {
        LOGD("ERROR ensureHooked: libbinder base not found");
        return false;
    }
    void** slots[4] = {nullptr, nullptr, nullptr, nullptr};
    int n = findGotSlots(base, sym, slots, 4);
    LOGD("libbinder path=%s base=%p inode=%lu dev=%lx slots=%d", path, (void*)base, (unsigned long)inode,
         (unsigned long)dev, n);
    if (n == 0) {
        LOGD("ERROR ensureHooked: no GOT slot for transact in libbinder");
        return false;
    }
    bool ok = false;
    for (int i = 0; i < n; i++) {
        void* cur = *slots[i];
        LOGD("slot[%d]=%p value=%p hook=%p orig=%p", i, (void*)slots[i], cur, (void*)transact_hook,
             (void*)transact_orig);
        if (cur == (void*)transact_hook) {
            LOGD("slot[%d] already hooked (zygisk plt hook worked)", i);
            ok = true;
            continue;
        }
        if (transact_orig == nullptr) transact_orig = (decltype(transact_orig))cur;
        if (patchGotSlot(slots[i], (void*)transact_hook) && *slots[i] == (void*)transact_hook) {
            LOGD("slot[%d] patched manually", i);
            ok = true;
        } else {
            LOGD("ERROR slot[%d] manual patch failed", i);
        }
    }
    return ok;
}

static size_t read_companion(int fd) {
    off_t size;
    if (read(fd, &size, sizeof(size)) < 0) {
        LOGD("ERROR read: %s", strerror(errno));
        return 0;
    }
    if (size <= 0) {
        LOGD("ERROR read_companion: size=%ld", size);
        return 0;
    }
    DETACH_TXT = (char*)malloc(size + 1);

    if (!readFullFromFd(fd, DETACH_TXT, size)) return 0;

    DETACH_TXT[size] = 0;
    return (size_t)size;
}

static bool runPreSpecialize(const char* process, zygisk::Api* api) {
    if (strncmp(process, VENDING_PROC, STR_LEN(VENDING_PROC)) != 0) return false;

    int fd = api->connectCompanion();
    size_t detach_len = read_companion(fd);
    close(fd);
    if (detach_len == 0) return false;

    return true;
}

static bool runPostSpecialize(const char* process, zygisk::Api* api, JNIEnv* env) {
    int sdk = android_get_device_api_level();
    if (sdk <= 0) {
        LOGD("ERROR android_get_device_api_level: %d", sdk);
        return false;
    }
    HEADERS_LEN = getBinderHeadersLen(sdk);

    getApplicationEnabledSetting_code = getStaticIntFieldJni(env, STUB("android/content/pm/IPackageManager"),
                                                             TRSCTN("getApplicationEnabledSetting"));
    if (getApplicationEnabledSetting_code == 0) return false;

    ino_t inode;
    dev_t dev;
    if (!getMapping("libbinder.so", &inode, &dev)) {
        LOGD("ERROR: Could not get libbinder");
        return false;
    }

    static const char* TRANSACT_SYM = "_ZN7android14IPCThreadState8transactEijRKNS_6ParcelEPS1_j";
    api->pltHookRegister(dev, inode, TRANSACT_SYM, (void**)&transact_hook, (void**)&transact_orig);
    if (!api->pltHookCommit()) {
        LOGD("WARN: pltHookCommit failed, will try manual GOT patch");
    }
    if (!ensureHooked(TRANSACT_SYM)) return false;

    LOGD("Loaded %s (sdk=%d hdr=%zu code=%u)", process, sdk, HEADERS_LEN, getApplicationEnabledSetting_code);
    return true;
}

class ZygiskDetach : public zygisk::ModuleBase {
   public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        process = env->GetStringUTFChars(args->nice_name, nullptr);
        doRunPost = runPreSpecialize(process, api);

        if (!doRunPost) {
            cleanup(args);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        if (!doRunPost) return;

        if (!runPostSpecialize(process, api, env)) {
            cleanup(args);
        }
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        (void)args;
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    void cleanup(const zygisk::AppSpecializeArgs* args) {
        free(DETACH_TXT);
        env->ReleaseStringUTFChars(args->nice_name, process);
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

   private:
    zygisk::Api* api;
    JNIEnv* env;

    bool doRunPost;
    const char* process;
};

static void companionHandler(int remote_fd) {
    companionSendFile("/data/adb/zygisk-detach/detach.bin", remote_fd);
}

REGISTER_ZYGISK_MODULE(ZygiskDetach)
REGISTER_ZYGISK_COMPANION(companionHandler)
