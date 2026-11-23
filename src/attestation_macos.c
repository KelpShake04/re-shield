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

    mach_vm_address_t addr = (mach_vm_address_t)(uintptr_t)code_ptr;
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
    if (kr != KERN_SUCCESS) {
        return RESHIELD_ATTEST_FAILED;
    }

    /* Code section must be executable and NOT writable (W^X) */
    if ((info.protection & VM_PROT_WRITE) != 0 || (info.protection & VM_PROT_EXECUTE) == 0) {
        return RESHIELD_ATTEST_FAILED;
    }
    return RESHIELD_ATTEST_OK;
#endif
}

reshield_attestation_status_t reshield_verify_os_codesign(void) {
#ifdef RESHIELD_DISABLE
    return RESHIELD_ATTEST_OK;
#else
    SecCodeRef self_code = NULL;
    OSStatus st = SecCodeCopySelf(kSecCSDefaultFlags, &self_code);
    if (st != errSecSuccess || self_code == NULL) {
        return RESHIELD_ATTEST_FAILED;
    }

    st = SecCodeCheckValidity(self_code, kSecCSDefaultFlags, NULL);
    CFRelease(self_code);
    return (st == errSecSuccess) ? RESHIELD_ATTEST_OK : RESHIELD_ATTEST_FAILED;
#endif
}

#else
typedef int reshield_attestation_macos_unused_t;
#endif
