#include "binder.hpp"

#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "module.hpp"

bool getMapping(const char* lib_name, ino_t* inode, dev_t* dev) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char mapbuf[256], flags[8];
    int lib_name_len = strlen(lib_name);
    while (fgets(mapbuf, sizeof(mapbuf), fp)) {
        unsigned int dev_major, dev_minor;
        int cur = 0;
        sscanf(mapbuf, "%*s %s %*x %x:%x %lu %*s%n", flags, &dev_major, &dev_minor, inode, &cur);
        if (cur < lib_name_len) continue;
        if (memcmp(&mapbuf[cur - lib_name_len], lib_name, lib_name_len) == 0 && flags[2] == 'x') {
            *dev = makedev(dev_major, dev_minor);
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}

#if defined(__LP64__)
typedef ElfW(Rela) Reloc;
#define R_SYM ELF64_R_SYM
#else
typedef ElfW(Rel) Reloc;
#define R_SYM ELF32_R_SYM
#endif

struct GotSearch {
    const char* lib;
    const char* symbol;
    GotSlot* slot;
    bool found;
};

static int gotSearchCb(dl_phdr_info* info, size_t, void* data) {
    auto s = (GotSearch*)data;
    const char* name = strrchr(info->dlpi_name, '/');
    if (name == nullptr || strcmp(name + 1, s->lib) != 0) return 0;

    uintptr_t bias = info->dlpi_addr;
    const ElfW(Dyn)* dyn = nullptr;
    uintptr_t relro_start = 0, relro_end = 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr)& ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_DYNAMIC) {
            dyn = (const ElfW(Dyn)*)(bias + ph.p_vaddr);
        } else if (ph.p_type == PT_GNU_RELRO) {
            relro_start = bias + ph.p_vaddr;
            relro_end = relro_start + ph.p_memsz;
        }
    }
    if (dyn == nullptr) return 1;

    // d_ptr values are link-time addresses, unless the linker already relocated them
    auto ptr = [&](uintptr_t p) { return p < bias ? p + bias : p; };
    uintptr_t symtab = 0, strtab = 0, jmprel = 0;
    size_t jmprel_size = 0;
    for (; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case DT_SYMTAB: symtab = ptr(dyn->d_un.d_ptr); break;
            case DT_STRTAB: strtab = ptr(dyn->d_un.d_ptr); break;
            case DT_JMPREL: jmprel = ptr(dyn->d_un.d_ptr); break;
            case DT_PLTRELSZ: jmprel_size = dyn->d_un.d_val; break;
        }
    }
    if (!symtab || !strtab || !jmprel) return 1;

    auto rel = (const Reloc*)jmprel;
    for (size_t i = 0; i < jmprel_size / sizeof(Reloc); i++) {
        auto sym = (const ElfW(Sym)*)symtab + R_SYM(rel[i].r_info);
        if (strcmp((const char*)strtab + sym->st_name, s->symbol) != 0) continue;
        uintptr_t addr = bias + rel[i].r_offset;
        s->slot->addr = (void**)addr;
        s->slot->relro = addr >= relro_start && addr < relro_end;
        s->found = true;
        break;
    }
    return 1;
}

bool findGotSlot(const char* lib, const char* symbol, GotSlot* slot) {
    GotSearch s = {lib, symbol, slot, false};
    dl_iterate_phdr(gotSearchCb, &s);
    return s.found;
}

bool writeGotSlot(const GotSlot& slot, void* value) {
    uintptr_t pagesz = sysconf(_SC_PAGESIZE);
    void* page = (void*)((uintptr_t)slot.addr & ~(pagesz - 1));
    if (mprotect(page, pagesz, PROT_READ | PROT_WRITE) != 0) {
        LOGD("ERROR mprotect: %s", strerror(errno));
        return false;
    }
    __atomic_store_n(slot.addr, value, __ATOMIC_RELAXED);
    if (slot.relro) mprotect(page, pagesz, PROT_READ);
    return true;
}

uint32_t getStaticIntFieldJni(JNIEnv* env, const char* cls_name, const char* field_name) {
    jclass cls = env->FindClass(cls_name);
    if (cls == nullptr) {
        env->ExceptionClear();
        LOGD("ERROR getStaticIntFieldJni: Could not get class '%s'", cls_name);
        return 0;
    }
    jfieldID field = env->GetStaticFieldID(cls, field_name, "I");
    if (field == nullptr) {
        env->ExceptionClear();
        LOGD("ERROR getStaticIntFieldJni: Could not get field %s.%s", cls_name, field_name);
        return 0;
    }
    jint val = env->GetStaticIntField(cls, field);
    return val;
}

void companionSendFile(const char* path, int remote_fd) {
    off_t size = 0;
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        LOGD("ERROR open: %s", strerror(errno));
        goto defer;
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        LOGD("ERROR fstat: %s", strerror(errno));
        goto defer;
    }
    size = st.st_size;

defer:
    if (write(remote_fd, &size, sizeof(size)) < 0) {
        LOGD("ERROR write: %s", strerror(errno));
        size = 0;
    }
    if (fd > 0) {
        if (size > 0 && sendfile(remote_fd, fd, NULL, size) < 0) {
            LOGD("ERROR sendfile: %s", strerror(errno));
        }
        close(fd);
    }
}

bool readFullFromFd(int fd, void* buf, off_t size) {
    off_t size_read = 0;
    while (size_read < size) {
        ssize_t ret = read(fd, (char*)buf + size_read, size - size_read);
        if (ret < 0) {
            LOGD("ERROR read: %s", strerror(errno));
            return false;
        } else {
            size_read += ret;
        }
    }
    return true;
}
