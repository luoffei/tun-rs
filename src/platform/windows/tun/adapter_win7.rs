use std::mem;

use windows::{
    core::PCWSTR,
    Win32::{
        Devices::{
            DeviceAndDriverInstallation::{
                SetupDiGetClassDevsExW, SetupDiGetDevicePropertyW, SETUP_DI_GET_CLASS_DEVS_FLAGS,
            },
            Properties::DEVPROP_TYPE_BINARY,
        },
        Foundation::{CloseHandle, ERROR_INVALID_DATA, FILETIME},
        System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    },
};

use crate::windows::{
    device::GUID_NETWORK_ADAPTER,
    ffi::{destroy_device_info_list, encode_utf16, enum_device_info},
    tun::adapter::{get_device_name, DEVPKEY_Wintun_OwningProcess},
};

#[repr(C)]
#[derive(Debug)]
pub struct OwningProcess {
    process_id: u32,
    creation_time: FILETIME,
}

pub fn check_adapter_if_orphaned_devices_win7(adapter_name: &str) -> bool {
    let device_name = encode_utf16("ROOT\\Wintun");
    let dev_info = match unsafe {
        SetupDiGetClassDevsExW(
            Some(&GUID_NETWORK_ADAPTER),
            PCWSTR::from_raw(device_name.as_ptr()),
            None,
            SETUP_DI_GET_CLASS_DEVS_FLAGS(0),
            None,
            None,
            None,
        )
    } {
        Ok(dev_info) => dev_info,
        Err(err) => {
            if err.code() == ERROR_INVALID_DATA.to_hresult() {
                log::error!("Failed to get adapters");
            }
            return false;
        }
    };

    let mut index = 0;
    let is_orphaned_adapter = loop {
        match enum_device_info(dev_info, index) {
            Some(ret) => {
                let Ok(devinfo_data) = ret else {
                    continue;
                };

                unsafe {
                    let mut ptype = mem::zeroed();
                    let mut buf: [u8; mem::size_of::<OwningProcess>()] = mem::zeroed();
                    let mut size = mem::zeroed();

                    if SetupDiGetDevicePropertyW(
                        dev_info,
                        &devinfo_data,
                        &DEVPKEY_Wintun_OwningProcess,
                        &mut ptype,
                        Some(&mut buf),
                        Some(&mut size),
                        0,
                    )
                    .is_ok()
                        && ptype == DEVPROP_TYPE_BINARY
                        && {
                            let owning_process = buf.as_ptr() as *const OwningProcess;
                            !process_is_stale(&*owning_process)
                        }
                    {
                        continue;
                    }
                }

                let Ok(name) = get_device_name(dev_info, &devinfo_data) else {
                    index += 1;
                    continue;
                };

                if adapter_name == &name {
                    break true;
                }
            }
            None => break false,
        }

        index += 1;
    };
    _ = destroy_device_info_list(dev_info);
    is_orphaned_adapter
}

fn process_is_stale(owning_process: &OwningProcess) -> bool {
    let Ok(process) = (unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            owning_process.process_id,
        )
    }) else {
        return true;
    };
    let mut creation_time: FILETIME = unsafe { std::mem::zeroed() };
    let mut unused: FILETIME = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        GetProcessTimes(
            process,
            &mut creation_time,
            &mut unused,
            &mut unused,
            &mut unused,
        )
    };
    _ = unsafe { CloseHandle(process) };
    if ret.is_err() {
        return false;
    }
    return creation_time.dwHighDateTime == owning_process.creation_time.dwHighDateTime
        && creation_time.dwLowDateTime == owning_process.creation_time.dwLowDateTime;
}
