#pragma once
#include <vector>
#include <string>
#include <mutex>
#include <bytehook.h>
#include "log.h"

class NativeHookTracker {
public:
    static NativeHookTracker& getInstance() {
        static NativeHookTracker instance;
        return instance;
    }

    void recordHook(const char* name, bool success) {
        std::lock_guard<std::mutex> lock(mutex_);
        total_++;
        if (success) {
            success_++;
        } else {
            failed_++;
            std::string failName = name ? name : "unknown";
            failed_names_.push_back(failName);
            LOGE("[QQEnhancedBypass] Native Hook 失败: %s", failName.c_str());
        }
    }

    int getTotal() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return total_;
    }

    int getSuccess() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return success_;
    }

    int getFailed() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return failed_;
    }

    std::string getFailedNames() const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (failed_names_.empty()) return "";
        std::string res;
        for (size_t i = 0; i < failed_names_.size(); i++) {
            if (i > 0) res += ", ";
            res += failed_names_[i];
        }
        return res;
    }

private:
    NativeHookTracker() : total_(0), success_(0), failed_(0) {}
    mutable std::mutex mutex_;
    int total_;
    int success_;
    int failed_;
    std::vector<std::string> failed_names_;
};

#define TRACK_NATIVE_HOOK_PARTIAL(filter, caller, callee, sym, fake_func, prev_func) \
    do { \
        bytehook_stub_t _stub = bytehook_hook_partial((filter), (caller), (callee), (sym), (void*)(fake_func), nullptr, (prev_func)); \
        NativeHookTracker::getInstance().recordHook((sym), _stub != nullptr); \
    } while(0)

#define TRACK_NATIVE_HOOK_SINGLE(caller, callee, sym, fake_func, hook_cb, prev_func) \
    do { \
        bytehook_stub_t _stub = bytehook_hook_single((caller), (callee), (sym), (void*)(fake_func), (hook_cb), (prev_func)); \
        NativeHookTracker::getInstance().recordHook((sym), _stub != nullptr); \
    } while(0)

#define TRACK_NATIVE_HOOK_ALL(callee, sym, fake_func, hook_cb, prev_func) \
    do { \
        bytehook_stub_t _stub = bytehook_hook_all((callee), (sym), (void*)(fake_func), (hook_cb), (prev_func)); \
        NativeHookTracker::getInstance().recordHook((sym), _stub != nullptr); \
    } while(0)
