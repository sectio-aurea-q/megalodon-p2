// Mach kernel FFI bindings for macOS process memory access
// These are the raw system calls needed to read another process's memory
// on macOS, including Apple Silicon.

#![allow(non_camel_case_types, dead_code)]

pub type mach_port_t = u32;
pub type kern_return_t = i32;
pub type vm_address_t = usize;
pub type vm_size_t = usize;
pub type mach_vm_address_t = u64;
pub type mach_vm_size_t = u64;
pub type vm_region_flavor_t = i32;
pub type vm_region_info_t = *mut i32;
pub type mach_msg_type_number_t = u32;
pub type memory_object_name_t = mach_port_t;
pub type vm_prot_t = i32;
pub type vm_inherit_t = u32;
pub type boolean_t = i32;
pub type vm_behavior_t = i32;
pub type vm_offset_t = usize;
pub type natural_t = u32;
pub type integer_t = i32;

pub const KERN_SUCCESS: kern_return_t = 0;
pub const VM_REGION_BASIC_INFO_64: vm_region_flavor_t = 9;
pub const VM_REGION_BASIC_INFO_COUNT_64: mach_msg_type_number_t = 9;

pub const VM_PROT_READ: vm_prot_t = 0x01;
pub const VM_PROT_WRITE: vm_prot_t = 0x02;
pub const VM_PROT_EXECUTE: vm_prot_t = 0x04;

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct vm_region_basic_info_64 {
    pub protection: vm_prot_t,
    pub max_protection: vm_prot_t,
    pub inheritance: vm_inherit_t,
    pub shared: boolean_t,
    pub reserved: boolean_t,
    pub offset: u64,
    pub behavior: vm_behavior_t,
    pub user_wired_count: u16,
}

extern "C" {
    pub fn mach_task_self() -> mach_port_t;

    pub fn task_for_pid(
        target_tport: mach_port_t,
        pid: i32,
        task: *mut mach_port_t,
    ) -> kern_return_t;

    pub fn mach_vm_region(
        target_task: mach_port_t,
        address: *mut mach_vm_address_t,
        size: *mut mach_vm_size_t,
        flavor: vm_region_flavor_t,
        info: vm_region_info_t,
        info_count: *mut mach_msg_type_number_t,
        object_name: *mut mach_port_t,
    ) -> kern_return_t;

    pub fn mach_vm_read_overwrite(
        target_task: mach_port_t,
        address: mach_vm_address_t,
        size: mach_vm_size_t,
        data: mach_vm_address_t,
        out_size: *mut mach_vm_size_t,
    ) -> kern_return_t;
}

/// Safe wrapper: get task port for a process
pub fn get_task_for_pid(pid: i32) -> Result<mach_port_t, String> {
    let mut task: mach_port_t = 0;
    let kr = unsafe { task_for_pid(mach_task_self(), pid, &mut task) };
    if kr != KERN_SUCCESS {
        Err(format!(
            "task_for_pid failed for PID {} (kern_return={}). Need root + SIP disabled.",
            pid, kr
        ))
    } else {
        Ok(task)
    }
}

/// Enumerate memory regions of a task
pub fn enumerate_regions(task: mach_port_t) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();
    let mut address: mach_vm_address_t = 0;

    loop {
        let mut size: mach_vm_size_t = 0;
        let mut info = vm_region_basic_info_64::default();
        let mut info_count = VM_REGION_BASIC_INFO_COUNT_64;
        let mut object_name: mach_port_t = 0;

        let kr = unsafe {
            mach_vm_region(
                task,
                &mut address,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                &mut info as *mut _ as vm_region_info_t,
                &mut info_count,
                &mut object_name,
            )
        };

        if kr != KERN_SUCCESS {
            break;
        }

        regions.push(MemoryRegion {
            address,
            size,
            protection: info.protection,
            shared: info.shared != 0,
        });

        address += size;
    }

    regions
}

/// Read memory from a task
pub fn read_memory(task: mach_port_t, address: mach_vm_address_t, size: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; size];
    let mut out_size: mach_vm_size_t = 0;

    let kr = unsafe {
        mach_vm_read_overwrite(
            task,
            address,
            size as mach_vm_size_t,
            buf.as_mut_ptr() as mach_vm_address_t,
            &mut out_size,
        )
    };

    if kr != KERN_SUCCESS {
        None
    } else {
        buf.truncate(out_size as usize);
        Some(buf)
    }
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub address: u64,
    pub size: u64,
    pub protection: vm_prot_t,
    pub shared: bool,
}

impl MemoryRegion {
    pub fn is_readable(&self) -> bool {
        self.protection & VM_PROT_READ != 0
    }

    pub fn is_writable(&self) -> bool {
        self.protection & VM_PROT_WRITE != 0
    }

    pub fn prot_string(&self) -> String {
        format!(
            "{}{}{}",
            if self.protection & VM_PROT_READ != 0 { "r" } else { "-" },
            if self.protection & VM_PROT_WRITE != 0 { "w" } else { "-" },
            if self.protection & VM_PROT_EXECUTE != 0 { "x" } else { "-" },
        )
    }
}
