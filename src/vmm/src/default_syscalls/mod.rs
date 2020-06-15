// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use seccomp::{
    Error, SeccompAction, SeccompCmpArgLen as ArgLen, SeccompCmpOp::Eq, SeccompCondition as Cond,
    SeccompRule,
};

#[macro_use]
mod macros;
mod filters;

pub use self::filters::default_filter;
pub use self::filters::get_seccomp_filter;

// See include/uapi/asm-generic/fcntl.h in the kernel code.
const FCNTL_FD_CLOEXEC: u64 = 1;
const FCNTL_F_SETFD: u64 = 2;

// See include/uapi/linux/futex.h in the kernel code.
const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_REQUEUE: u64 = 3;
#[cfg(target_env = "gnu")]
const FUTEX_CMP_REQUEUE: u64 = 4;
const FUTEX_PRIVATE_FLAG: u64 = 128;
const FUTEX_WAIT_PRIVATE: u64 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
const FUTEX_WAKE_PRIVATE: u64 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;
const FUTEX_REQUEUE_PRIVATE: u64 = FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG;
#[cfg(target_env = "gnu")]
const FUTEX_CMP_REQUEUE_PRIVATE: u64 = FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG;

// See include/uapi/asm-generic/ioctls.h in the kernel code.
const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TIOCGWINSZ: u64 = 0x5413;
const FIOCLEX: u64 = 0x5451;
const FIONBIO: u64 = 0x5421;

// Hardcoded here instead of getting values from kvm-ioctls, so that filtered values cannot be
// mistakenly or intentionally altered from outside our codebase.

// See include/uapi/linux/if_tun.h in the kernel code.
const KVM_GET_API_VERSION: u64 = 0xae00;
const KVM_CREATE_VM: u64 = 0xae01;
const KVM_CHECK_EXTENSION: u64 = 0xae03;
const KVM_GET_VCPU_MMAP_SIZE: u64 = 0xae04;
const KVM_CREATE_VCPU: u64 = 0xae41;
const KVM_SET_TSS_ADDR: u64 = 0xae47;
const KVM_CREATE_IRQCHIP: u64 = 0xae60;
const KVM_RUN: u64 = 0xae80;
const KVM_SET_MSRS: u64 = 0x4008_ae89;
const KVM_SET_CPUID2: u64 = 0x4008_ae90;
const KVM_SET_USER_MEMORY_REGION: u64 = 0x4020_ae46;
const KVM_IRQFD: u64 = 0x4020_ae76;
const KVM_CREATE_PIT2: u64 = 0x4040_ae77;
const KVM_IOEVENTFD: u64 = 0x4040_ae79;
const KVM_SET_REGS: u64 = 0x4090_ae82;
const KVM_SET_SREGS: u64 = 0x4138_ae84;
const KVM_SET_FPU: u64 = 0x41a0_ae8d;
const KVM_SET_LAPIC: u64 = 0x4400_ae8f;
const KVM_GET_SREGS: u64 = 0x8138_ae83;
const KVM_GET_LAPIC: u64 = 0x8400_ae8e;
const KVM_GET_MSR_INDEX_LIST: u64 = 0xc004_ae02;
const KVM_GET_MSR_FEATURE_INDEX_LIST: u64 = 0xc004_ae0a;
const KVM_GET_SUPPORTED_CPUID: u64 = 0xc008_ae05;
const KVM_GET_IRQCHIP: u64 = 0xc208_ae62;
const KVM_SET_IRQCHIP: u64 = 0x8208_ae63;
const KVM_SET_CLOCK: u64 = 0x4030_ae7b;
const KVM_GET_CLOCK: u64 = 0x8030_ae7c;
const KVM_GET_PIT2: u64 = 0x8070_ae9f;
const KVM_SET_PIT2: u64 = 0x4070_aea0;
const KVM_GET_REGS: u64 = 0x8090_ae81;
const KVM_GET_MSRS: u64 = 0xc008_ae88;
const KVM_GET_CPUID2: u64 = 0xc008_ae91;
const KVM_GET_MP_STATE: u64 = 0x8004_ae98;
const KVM_SET_MP_STATE: u64 = 0x4004_ae99;
const KVM_GET_VCPU_EVENTS: u64 = 0x8040_ae9f;
const KVM_SET_VCPU_EVENTS: u64 = 0x4040_aea0;
const KVM_GET_DEBUGREGS: u64 = 0x8080_aea1;
const KVM_SET_DEBUGREGS: u64 = 0x4080_aea2;
const KVM_GET_XSAVE: u64 = 0x9000_aea4;
const KVM_SET_XSAVE: u64 = 0x5000_aea5;
const KVM_GET_XCRS: u64 = 0x8188_aea6;
const KVM_SET_XCRS: u64 = 0x4188_aea7;

// See include/uapi/linux/if_tun.h in the kernel code.
const TUNSETIFF: u64 = 0x4004_54ca;
const TUNSETOFFLOAD: u64 = 0x4004_54d0;
const TUNSETVNETHDRSZ: u64 = 0x4004_54d8;

fn create_ioctl_seccomp_rule() -> Result<Vec<SeccompRule>, Error> {
    Ok(or![
        and![Cond::new(1, ArgLen::DWORD, Eq, TCSETS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TCGETS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TIOCGWINSZ)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_CHECK_EXTENSION,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_CREATE_VM)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_API_VERSION,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_SUPPORTED_CPUID,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_VCPU_MMAP_SIZE,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_CREATE_IRQCHIP,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_CREATE_PIT2)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_CREATE_VCPU)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_IOEVENTFD)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_IRQFD)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_TSS_ADDR,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_USER_MEMORY_REGION,)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, FIOCLEX)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, FIONBIO)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TUNSETIFF)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TUNSETOFFLOAD)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, TUNSETVNETHDRSZ)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_LAPIC)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_SREGS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_RUN)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_CPUID2)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_FPU)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_LAPIC)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_MSRS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_REGS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_SREGS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_MSR_INDEX_LIST)?],
        and![Cond::new(
            1,
            ArgLen::DWORD,
            Eq,
            KVM_GET_MSR_FEATURE_INDEX_LIST
        )?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_IRQCHIP)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_IRQCHIP)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_CLOCK)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_CLOCK)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_PIT2)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_PIT2)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_REGS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_MSRS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_CPUID2)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_MP_STATE)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_MP_STATE)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_VCPU_EVENTS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_VCPU_EVENTS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_DEBUGREGS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_DEBUGREGS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_XSAVE)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_XSAVE)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_GET_XCRS)?],
        and![Cond::new(1, ArgLen::DWORD, Eq, KVM_SET_XCRS)?],
    ])
}

#[cfg(test)]
#[cfg(target_env = "musl")]
mod tests {
    use super::*;
    use seccomp::SeccompFilter;
    use std::convert::TryInto;
    use std::thread;

    const EXTRA_SYSCALLS: [i64; 5] = [
        libc::SYS_clone,
        libc::SYS_mprotect,
        libc::SYS_rt_sigprocmask,
        libc::SYS_set_tid_address,
        libc::SYS_sigaltstack,
    ];

    fn add_syscalls_install_filter(mut filter: SeccompFilter) {
        // Test error case: add empty rule array.
        assert!(filter.add_rules(0, vec![],).is_err());
        // Add "Allow" rule for each syscall.
        for syscall in EXTRA_SYSCALLS.iter() {
            assert!(filter
                .add_rules(
                    *syscall,
                    vec![SeccompRule::new(vec![], SeccompAction::Allow)],
                )
                .is_ok());
        }
        assert!(SeccompFilter::apply(filter.try_into().unwrap()).is_ok());
    }

    #[test]
    fn test_basic_seccomp() {
        // Spawn a new thread before running the tests because all tests run
        // in the same thread. Otherwise other tests will fail because of the
        // installed seccomp filters.
        thread::spawn(move || {
            let filter = default_filter().unwrap().allow_all();
            add_syscalls_install_filter(filter);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn test_advanced_seccomp() {
        // Spawn a new thread before running the tests because all tests run
        // in the same thread. Otherwise other tests will fail because of the
        // installed seccomp filters.
        thread::spawn(move || {
            let filter = default_filter().unwrap();
            add_syscalls_install_filter(filter);
        })
        .join()
        .unwrap();
    }
}
