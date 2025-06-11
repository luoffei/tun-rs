use std::{io, mem};

use scopeguard::defer;
use windows::{
    core::GUID,
    Win32::{
        Devices::{
            DeviceAndDriverInstallation::{
                CM_Get_DevNode_Status, CM_DEVNODE_STATUS_FLAGS, CM_PROB, CR_SUCCESS, DIF_REMOVE,
                DI_REMOVEDEVICE_GLOBAL, DN_HAS_PROBLEM, HDEVINFO, SETUP_DI_GET_CLASS_DEVS_FLAGS,
                SP_CLASSINSTALL_HEADER, SP_DEVINFO_DATA, SP_REMOVEDEVICE_PARAMS,
            },
            Properties::DEVPROPID_FIRST_USABLE,
        },
        Foundation::DEVPROPKEY,
        System::SystemInformation::{GetVersionExA, OSVERSIONINFOA},
    },
};

use crate::windows::{device::GUID_NETWORK_ADAPTER, ffi};

#[allow(non_upper_case_globals)]
pub const DEVPKEY_Wintun_OwningProcess: DEVPROPKEY = DEVPROPKEY {
    fmtid: GUID {
        data1: 0x3361c968,
        data2: 0x2f2e,
        data3: 0x4660,
        data4: [0xb4, 0x7e, 0x69, 0x9c, 0xdc, 0x4c, 0x32, 0xb9],
    },
    pid: DEVPROPID_FIRST_USABLE + 3,
};

pub fn check_adapter_if_orphaned_devices(adapter_name: &str) -> bool {
    if is_windows_seven() {
        return super::adapter_win7::check_adapter_if_orphaned_devices_win7(adapter_name);
    }

    let Ok(dev_info) = ffi::get_class_devs(
        &GUID_NETWORK_ADAPTER,
        Some("SWD\\Wintun"),
        SETUP_DI_GET_CLASS_DEVS_FLAGS(0),
    ) else {
        log::error!("Failed to get adapters");
        return false;
    };

    defer! {
        _ = ffi::destroy_device_info_list(dev_info);
    }

    let mut index = 0;
    let is_orphaned_adapter = loop {
        match ffi::enum_device_info(dev_info, index) {
            Some(ret) => {
                let Ok(devinfo_data) = ret else {
                    continue;
                };

                let Ok(status) = dev_node_status(&devinfo_data) else {
                    index += 1;
                    continue;
                };
                if status.0 & DN_HAS_PROBLEM.0 == 0 {
                    index += 1;
                    continue;
                }

                let Ok(name) = ffi::get_device_name(dev_info, &devinfo_data) else {
                    index += 1;
                    continue;
                };

                if adapter_name == name {
                    break true;
                }
            }
            None => break false,
        }

        index += 1;
    };

    is_orphaned_adapter
}

#[allow(dead_code)]
pub fn adapter_remove_instance(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
) -> io::Result<()> {
    let remove_device_params = SP_REMOVEDEVICE_PARAMS {
        ClassInstallHeader: SP_CLASSINSTALL_HEADER {
            cbSize: mem::size_of::<SP_CLASSINSTALL_HEADER>() as _,
            InstallFunction: DIF_REMOVE,
        },
        Scope: DI_REMOVEDEVICE_GLOBAL,
        HwProfile: 0,
    };

    ffi::call_class_install_params(
        devinfo,
        devinfo_data,
        &remove_device_params.ClassInstallHeader,
        mem::size_of::<SP_REMOVEDEVICE_PARAMS>() as _,
    )?;

    ffi::call_class_installer(devinfo, devinfo_data, DIF_REMOVE)?;

    Ok(())
}

fn is_windows_seven() -> bool {
    let mut info: OSVERSIONINFOA = Default::default();
    info.dwOSVersionInfoSize = mem::size_of::<OSVERSIONINFOA>() as u32;

    unsafe {
        if let Err(err) = GetVersionExA(&mut info) {
            log::error!(target: "app", "GetVersionExA: {err}");
            return false;
        }
    }

    info.dwMajorVersion == 6 && info.dwMinorVersion == 1
}

fn dev_node_status(devinfo_data: &SP_DEVINFO_DATA) -> io::Result<CM_DEVNODE_STATUS_FLAGS> {
    let mut pulstatus = CM_DEVNODE_STATUS_FLAGS(0);
    let mut pulproblemnumber = CM_PROB(0);

    let cr = unsafe {
        CM_Get_DevNode_Status(
            &mut pulstatus,
            &mut pulproblemnumber,
            devinfo_data.DevInst,
            0,
        )
    };

    if cr != CR_SUCCESS {
        return Err(io::Error::last_os_error());
    }

    Ok(pulstatus)
}
