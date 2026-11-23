#if defined(__APPLE__) && defined(__MACH__)

#include "reshield/attestation.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdint.h>

extern int reshield_platform_get_code_section(const uint8_t **out_ptr, uint64_t *out_size);

reshield_attestation_status_t reshield_verify_code_page_wx(void) {
#ifdef RESHIELD_DISABLE
    return RESHIELD_ATTEST_OK;
#else
    const uint8_t *code_ptr = NULL;
    uint64_t code_size = 0;
    if (reshield_platform_get_code_section(&code_ptr, &code_size) != 0 ||
        code_ptr == NULL || code_size == 0) {
        return RESHIELD_ATTEST_FAILED;
    }

    /* The whole [start, end) range must be covered by contiguous regions that are all
     * executable and NOT writable; a gap between regions is a failure. */
    mach_vm_address_t start = (mach_vm_address_t)(uintptr_t)code_ptr;
    if (code_size > UINT64_MAX - start) {
        return RESHIELD_ATTEST_FAILED;
    }
    mach_vm_address_t end = start + (mach_vm_address_t)code_size;

    mach_vm_address_t cur = start;
    while (cur < end) {
        mach_vm_address_t addr = cur;
        mach_vm_size_t vmsize = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object_name = MACH_PORT_NULL;

        kern_return_t kr = mach_vm_region(
            mach_task_self(),
            &addr,
            &vmsize,
            VM_REGION_BASIC_INFO_64,
            (vm_region_info_t)&info,
            &count,
            &object_name
        );
        if (object_name != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), object_name);
        }
        if (kr != KERN_SUCCESS || addr > cur || vmsize == 0 || vmsize > UINT64_MAX - addr) {
            return RESHIELD_ATTEST_FAILED;
        }

        if ((info.protection & VM_PROT_WRITE) != 0 || (info.protection & VM_PROT_EXECUTE) == 0) {
            return RESHIELD_ATTEST_FAILED;
        }
        cur = addr + vmsize;
    }
    return RESHIELD_ATTEST_OK;
#endif
}

reshield_attestation_status_t reshield_verify_os_codesign_req(const char *requirement) {
#ifdef RESHIELD_DISABLE
    (void)requirement;
    return RESHIELD_ATTEST_OK;
#else
    SecRequirementRef req = NULL;
    if (requirement != NULL) {
        /* A requirement string that does not parse fails closed: a typo must not
         * silently turn the signer pin off. */
        CFStringRef req_str = CFStringCreateWithCString(NULL, requirement, kCFStringEncodingUTF8);
        if (req_str == NULL) {
            return RESHIELD_ATTEST_FAILED;
        }
        OSStatus rst = SecRequirementCreateWithString(req_str, kSecCSDefaultFlags, &req);
        CFRelease(req_str);
        if (rst != errSecSuccess || req == NULL) {
            return RESHIELD_ATTEST_FAILED;
        }
    }

    SecCodeRef self_code = NULL;
    OSStatus st = SecCodeCopySelf(kSecCSDefaultFlags, &self_code);
    if (st != errSecSuccess || self_code == NULL) {
        if (req != NULL) CFRelease(req);
        return RESHIELD_ATTEST_FAILED;
    }

    st = SecCodeCheckValidity(self_code, kSecCSDefaultFlags, req);
    CFRelease(self_code);
    if (req != NULL) CFRelease(req);
    return (st == errSecSuccess) ? RESHIELD_ATTEST_OK : RESHIELD_ATTEST_FAILED;
#endif
}

#else
typedef int reshield_attestation_macos_unused_t;
#endif
