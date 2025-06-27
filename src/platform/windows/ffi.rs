use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::{io, mem, ptr, slice};

use scopeguard::defer;
use windows::core::PCWSTR;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiBuildDriverInfoList, SetupDiCallClassInstaller, SetupDiClassNameFromGuidW,
    SetupDiCreateDeviceInfoList, SetupDiCreateDeviceInfoW, SetupDiDestroyDeviceInfoList,
    SetupDiDestroyDriverInfoList, SetupDiEnumDeviceInfo, SetupDiEnumDriverInfoW,
    SetupDiGetClassDevsW, SetupDiGetDevicePropertyW, SetupDiGetDeviceRegistryPropertyW,
    SetupDiGetDriverInfoDetailW, SetupDiOpenDevRegKey, SetupDiSetClassInstallParamsW,
    SetupDiSetDeviceRegistryPropertyW, SetupDiSetSelectedDevice, SetupDiSetSelectedDriverW,
    DI_FUNCTION, HDEVINFO, MAX_CLASS_NAME_LEN, SETUP_DI_DEVICE_CREATION_FLAGS,
    SETUP_DI_DRIVER_TYPE, SETUP_DI_GET_CLASS_DEVS_FLAGS, SETUP_DI_REGISTRY_PROPERTY,
    SP_CLASSINSTALL_HEADER, SP_DEVINFO_DATA, SP_DRVINFO_DATA_V2_W, SP_DRVINFO_DETAIL_DATA_W,
};
use windows::Win32::Devices::Properties::DEVPROPID_FIRST_USABLE;
use windows::Win32::Foundation::{
    DEVPROPKEY, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_PENDING, ERROR_NO_MORE_ITEMS,
    ERROR_OBJECT_ALREADY_EXISTS, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToGuid,
    ConvertInterfaceLuidToIndex, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
    DeleteUnicastIpAddressEntry, FreeMibTable, GetIpInterfaceEntry, GetIpInterfaceTable,
    GetUnicastIpAddressTable, InitializeIpForwardEntry, InitializeUnicastIpAddressEntry,
    SetIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_IPINTERFACE_TABLE,
    MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetConnection, INetConnectionManager, NCME_DEFAULT,
};
use windows::Win32::Networking::WinSock::{
    NlroManual, AF_INET, AF_INET6, AF_UNSPEC, MIB_IPPROTO_NETMGMT,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_SHARE_MODE,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoUninitialize, StringFromGUID2,
    CLSCTX_ALL, COINIT_APARTMENTTHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Registry::{RegNotifyChangeKeyValue, HKEY, REG_NOTIFY_FILTER};
use windows::Win32::System::Threading::{
    CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
};
use windows::Win32::System::IO::{
    CancelIoEx, DeviceIoControl, GetOverlappedResult, OVERLAPPED, OVERLAPPED_0, OVERLAPPED_0_0,
};
use windows::{
    core::{GUID, HRESULT},
    Win32::{
        Foundation::{ERROR_SUCCESS, WIN32_ERROR},
        Networking::WinSock::SOCKADDR_INET,
    },
};

#[allow(non_upper_case_globals)]
pub const DEVPKEY_Wintun_Name: DEVPROPKEY = DEVPROPKEY {
    fmtid: GUID {
        data1: 0x3361c968,
        data2: 0x2f2e,
        data3: 0x4660,
        data4: [0xb4, 0x7e, 0x69, 0x9c, 0xdc, 0x4c, 0x32, 0xb9],
    },
    pid: DEVPROPID_FIRST_USABLE + 1,
};

pub fn error_map(err: windows::core::Error) -> io::Error {
    io::Error::from(err)
}

fn winapi_result(result: WIN32_ERROR) -> io::Result<()> {
    if result == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(
            HRESULT::from_win32(result.0).0,
        ))
    }
}

fn convert_sockaddr(sa: SOCKADDR_INET) -> SocketAddr {
    unsafe {
        match sa.si_family {
            AF_INET => SocketAddr::new(
                Ipv4Addr::from(sa.Ipv4.sin_addr).into(),
                u16::from_be(sa.Ipv4.sin_port),
            ),
            AF_INET6 => SocketAddr::new(
                Ipv6Addr::from(sa.Ipv6.sin6_addr).into(),
                u16::from_be(sa.Ipv6.sin6_port),
            ),
            _ => panic!("Invalid address family"),
        }
    }
}

/// Encode a string as a utf16 buffer
pub fn encode_utf16(string: &str) -> Vec<u16> {
    use std::iter::once;
    string.encode_utf16().chain(once(0)).collect()
}

pub fn decode_utf16(string: &[u16]) -> String {
    let end = string.iter().position(|b| *b == 0).unwrap_or(string.len());
    String::from_utf16_lossy(&string[..end])
}

pub fn decode_utf8(buf: &[u8]) -> String {
    let u16_count = (buf.len() as usize) / 2;
    let wide: &[u16] = unsafe { slice::from_raw_parts(buf.as_ptr() as *const u16, u16_count) };
    decode_utf16(wide)
}

pub fn string_from_guid(guid: &GUID) -> io::Result<String> {
    let mut string = vec![0; 39];

    match unsafe { StringFromGUID2(guid, string.as_mut_slice()) } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(decode_utf16(&string)),
    }
}

pub fn alias_to_luid(alias: &str) -> io::Result<NET_LUID_LH> {
    let alias = encode_utf16(alias);
    let mut luid = unsafe { mem::zeroed() };
    let result =
        unsafe { ConvertInterfaceAliasToLuid(PCWSTR::from_raw(alias.as_ptr()), &mut luid) };
    winapi_result(result)?;
    Ok(luid)
}

pub fn luid_to_index(luid: &NET_LUID_LH) -> io::Result<u32> {
    let mut index = 0;
    let result = unsafe { ConvertInterfaceLuidToIndex(luid, &mut index) };
    winapi_result(result)?;
    Ok(index)
}

pub fn luid_to_guid(luid: &NET_LUID_LH) -> io::Result<GUID> {
    let mut guid = unsafe { mem::zeroed() };
    let result = unsafe { ConvertInterfaceLuidToGuid(luid, &mut guid) };
    winapi_result(result)?;
    Ok(guid)
}

pub fn luid_to_alias(luid: &NET_LUID_LH) -> io::Result<String> {
    // IF_MAX_STRING_SIZE + 1
    let mut alias = vec![0; 257];
    let result = unsafe { ConvertInterfaceLuidToAlias(luid, &mut alias) };
    winapi_result(result)?;
    Ok(decode_utf16(&alias))
}
pub fn reset_event(handle: RawHandle) -> io::Result<()> {
    unsafe { ResetEvent(HANDLE(handle)).map_err(error_map) }
}
pub fn wait_for_single_object(handle: RawHandle, timeout: u32) -> io::Result<()> {
    let wait_event = unsafe { WaitForSingleObject(HANDLE(handle), timeout) };
    if wait_event == WAIT_OBJECT_0 {
        return Ok(());
    }

    Err(io::Error::last_os_error())
}
pub fn set_event(handle: RawHandle) -> io::Result<()> {
    unsafe { SetEvent(HANDLE(handle)).map_err(error_map) }
}
pub fn create_event() -> io::Result<OwnedHandle> {
    unsafe {
        CreateEventW(None, true, false, None)
            .map(|handle| OwnedHandle::from_raw_handle(handle.0))
            .map_err(error_map)
    }
}

pub fn create_file(
    file_name: &str,
    desired_access: u32,
    share_mode: FILE_SHARE_MODE,
    creation_disposition: FILE_CREATION_DISPOSITION,
    flags_and_attributes: FILE_FLAGS_AND_ATTRIBUTES,
) -> io::Result<HANDLE> {
    let file_name = encode_utf16(file_name);
    unsafe {
        CreateFileW(
            PCWSTR::from_raw(file_name.as_ptr()),
            desired_access,
            share_mode,
            None,
            creation_disposition,
            flags_and_attributes,
            None,
        )
    }
    .map_err(error_map)
}

pub fn io_overlapped() -> OVERLAPPED {
    OVERLAPPED {
        Internal: 0,
        InternalHigh: 0,
        Anonymous: OVERLAPPED_0 {
            Anonymous: OVERLAPPED_0_0 {
                Offset: 0,
                OffsetHigh: 0,
            },
        },
        hEvent: HANDLE::default(),
    }
}

pub fn try_read_file(
    handle: HANDLE,
    io_overlapped: &mut OVERLAPPED,
    buffer: &mut [u8],
) -> io::Result<u32> {
    let mut ret = 0;
    //https://www.cnblogs.com/linyilong3/archive/2012/05/03/2480451.html
    unsafe { ReadFile(handle, Some(buffer), Some(&mut ret), Some(io_overlapped)) }
        .map_err(error_map)?;
    Ok(ret)
}

pub fn try_write_file(
    handle: HANDLE,
    io_overlapped: &mut OVERLAPPED,
    buffer: &[u8],
) -> io::Result<u32> {
    let mut ret = 0;
    unsafe { WriteFile(handle, Some(buffer), Some(&mut ret), Some(io_overlapped)) }
        .map_err(error_map)?;
    Ok(ret)
}

pub fn try_io_overlapped(handle: HANDLE, io_overlapped: &OVERLAPPED) -> io::Result<u32> {
    let mut ret = 0;
    unsafe { GetOverlappedResult(handle, io_overlapped, &mut ret, false) }.map_err(error_map)?;
    Ok(ret)
}
#[allow(dead_code)]
pub fn cancel_io_overlapped(handle: HANDLE, io_overlapped: &OVERLAPPED) -> io::Result<u32> {
    unsafe {
        _ = CancelIoEx(handle, Some(io_overlapped));
        wait_io_overlapped(handle, io_overlapped)
    }
}

pub fn read_file(
    handle: HANDLE,
    buffer: &mut [u8],
    cancel_event: Option<RawHandle>,
) -> io::Result<u32> {
    let mut ret = 0;
    //https://www.cnblogs.com/linyilong3/archive/2012/05/03/2480451.html
    unsafe {
        let mut io_overlapped = io_overlapped();
        let io_event = create_event()?;
        io_overlapped.hEvent = HANDLE(io_event.as_raw_handle());

        match ReadFile(
            handle,
            Some(buffer),
            Some(&mut ret),
            Some(&mut io_overlapped),
        ) {
            Ok(_) => Ok(ret),
            Err(err) => {
                let err = error_map(err);
                if err.raw_os_error().unwrap_or(0) == ERROR_IO_PENDING.0 as i32 {
                    if let Some(cancel_event) = cancel_event {
                        wait_io_overlapped_cancelable(handle, &io_overlapped, cancel_event)
                    } else {
                        wait_io_overlapped(handle, &io_overlapped)
                    }
                } else {
                    Err(err)
                }
            }
        }
    }
}

pub fn write_file(
    handle: HANDLE,
    buffer: &[u8],
    cancel_event: Option<RawHandle>,
) -> io::Result<u32> {
    let mut ret = 0;
    let mut io_overlapped = io_overlapped();
    let io_event = create_event()?;
    io_overlapped.hEvent = HANDLE(io_event.as_raw_handle());
    unsafe {
        match WriteFile(
            handle,
            Some(buffer),
            Some(&mut ret),
            Some(&mut io_overlapped),
        ) {
            Ok(_) => Ok(ret),
            Err(err) => {
                let err = error_map(err);

                if err.raw_os_error().unwrap_or(0) == ERROR_IO_PENDING.0 as i32 {
                    if let Some(cancel_event) = cancel_event {
                        wait_io_overlapped_cancelable(handle, &io_overlapped, cancel_event)
                    } else {
                        wait_io_overlapped(handle, &io_overlapped)
                    }
                } else {
                    Err(err)
                }
            }
        }
    }
}

pub fn wait_io_overlapped(handle: HANDLE, io_overlapped: &OVERLAPPED) -> io::Result<u32> {
    let mut ret = 0;
    unsafe { GetOverlappedResult(handle, io_overlapped, &mut ret, true) }.map_err(error_map)?;
    Ok(ret)
}
pub fn wait_io_overlapped_cancelable(
    handle: HANDLE,
    io_overlapped: &OVERLAPPED,
    cancel_event: RawHandle,
) -> io::Result<u32> {
    let handles = [io_overlapped.hEvent, HANDLE(cancel_event)];
    unsafe {
        let wait_ret = WaitForMultipleObjects(&handles, false, INFINITE);
        match wait_ret {
            WAIT_OBJECT_0 => {
                let mut transferred = 0u32;
                GetOverlappedResult(handle, io_overlapped, &mut transferred, false)
                    .map_err(error_map)?;
                Ok(transferred)
            }
            _ => {
                if wait_ret.0 == WAIT_OBJECT_0.0 + 1 {
                    _ = CancelIoEx(handle, Some(io_overlapped));
                    _ = WaitForSingleObject(io_overlapped.hEvent, INFINITE);
                    Err(io::Error::new(io::ErrorKind::Interrupted, "cancel"))
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }
    }
}

pub fn create_device_info_list(guid: &GUID) -> io::Result<HDEVINFO> {
    unsafe { SetupDiCreateDeviceInfoList(Some(guid), None) }.map_err(error_map)
}

pub fn get_class_devs(
    guid: &GUID,
    enumerator: Option<&str>,
    flags: SETUP_DI_GET_CLASS_DEVS_FLAGS,
) -> io::Result<HDEVINFO> {
    let enumerator =
        enumerator.map(|enumerator| PCWSTR::from_raw(encode_utf16(enumerator).as_ptr()));
    unsafe {
        SetupDiGetClassDevsW(
            Some(guid),
            enumerator.unwrap_or(PCWSTR::null()),
            None,
            flags,
        )
    }
    .map_err(error_map)
}

pub fn destroy_device_info_list(devinfo: HDEVINFO) -> io::Result<()> {
    unsafe { SetupDiDestroyDeviceInfoList(devinfo) }.map_err(error_map)
}

pub fn class_name_from_guid(guid: &GUID) -> io::Result<String> {
    let mut class_name = vec![0; MAX_CLASS_NAME_LEN as usize];
    let mut required_size = 0;
    unsafe { SetupDiClassNameFromGuidW(guid, &mut class_name, Some(&mut required_size)) }
        .map_err(error_map)?;
    Ok(decode_utf16(&class_name[..required_size as _]))
}

pub fn create_device_info(
    devinfo: HDEVINFO,
    device_name: &str,
    guid: &GUID,
    device_description: &str,
    creation_flags: SETUP_DI_DEVICE_CREATION_FLAGS,
) -> io::Result<SP_DEVINFO_DATA> {
    let mut devinfo_data: SP_DEVINFO_DATA = unsafe { mem::zeroed() };
    devinfo_data.cbSize = mem::size_of_val(&devinfo_data) as _;
    let device_name = encode_utf16(device_name);
    let device_description = encode_utf16(device_description);
    unsafe {
        SetupDiCreateDeviceInfoW(
            devinfo,
            PCWSTR::from_raw(device_name.as_ptr()),
            guid,
            PCWSTR::from_raw(device_description.as_ptr()),
            None,
            creation_flags,
            Some(&mut devinfo_data),
        )
    }
    .map_err(error_map)?;
    Ok(devinfo_data)
}

pub fn set_selected_device(devinfo: HDEVINFO, devinfo_data: &SP_DEVINFO_DATA) -> io::Result<()> {
    unsafe { SetupDiSetSelectedDevice(devinfo, devinfo_data as *const _ as _) }.map_err(error_map)
}

pub fn set_device_registry_property(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    property: SETUP_DI_REGISTRY_PROPERTY,
    value: &str,
) -> io::Result<()> {
    let wide = encode_utf16(value);
    let buf = unsafe { slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2) };

    unsafe {
        SetupDiSetDeviceRegistryPropertyW(
            devinfo,
            devinfo_data as *const _ as _,
            property,
            Some(buf),
        )
    }
    .map_err(error_map)
}

pub fn get_device_registry_property(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    property: SETUP_DI_REGISTRY_PROPERTY,
) -> io::Result<String> {
    let mut value = vec![0; 32];
    let mut size = 0;

    unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            devinfo,
            devinfo_data,
            property,
            None,
            Some(&mut value),
            Some(&mut size),
        )
    }
    .map_err(error_map)?;

    Ok(decode_utf8(&value[..size as _]))
}

pub fn build_driver_info_list(
    devinfo: HDEVINFO,
    devinfo_data: &mut SP_DEVINFO_DATA,
    driver_type: SETUP_DI_DRIVER_TYPE,
) -> io::Result<()> {
    unsafe { SetupDiBuildDriverInfoList(devinfo, Some(devinfo_data), driver_type) }
        .map_err(error_map)
}

pub fn destroy_driver_info_list(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    driver_type: SETUP_DI_DRIVER_TYPE,
) -> io::Result<()> {
    unsafe { SetupDiDestroyDriverInfoList(devinfo, Some(devinfo_data), driver_type) }
        .map_err(error_map)
}

pub fn get_driver_hardware_id(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    drvinfo_data: &SP_DRVINFO_DATA_V2_W,
) -> io::Result<String> {
    unsafe {
        let mut required_size = 0;
        let _ = SetupDiGetDriverInfoDetailW(
            devinfo,
            Some(devinfo_data),
            drvinfo_data,
            None,
            0,
            Some(&mut required_size),
        );

        let mut raw: Vec<u8> = vec![0; required_size as usize];
        let p = raw.as_mut_ptr() as *mut SP_DRVINFO_DETAIL_DATA_W;
        (*p).cbSize = mem::size_of::<SP_DRVINFO_DETAIL_DATA_W>() as _;

        SetupDiGetDriverInfoDetailW(
            devinfo,
            Some(devinfo_data),
            drvinfo_data,
            Some(&mut *p),
            required_size,
            None,
        )
        .map_err(error_map)?;

        let hw_off = mem::offset_of!(SP_DRVINFO_DETAIL_DATA_W, HardwareID);
        let wide_ptr = raw.as_ptr().add(hw_off) as *const u16;

        let wide_len = (required_size as usize - hw_off) / 2;
        let wide_slice = slice::from_raw_parts(wide_ptr, wide_len);

        Ok(decode_utf16(wide_slice))
    }
}

pub fn set_selected_driver(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    drvinfo_data: &SP_DRVINFO_DATA_V2_W,
) -> io::Result<()> {
    unsafe {
        SetupDiSetSelectedDriverW(
            devinfo,
            Some(devinfo_data as *const _ as _),
            Some(drvinfo_data as *const _ as _),
        )
    }
    .map_err(error_map)
}

pub fn call_class_install_params(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    header: &SP_CLASSINSTALL_HEADER,
    params_size: u32,
) -> io::Result<()> {
    unsafe {
        SetupDiSetClassInstallParamsW(devinfo, Some(devinfo_data), Some(header), params_size)
            .map_err(error_map)
    }
}

pub fn call_class_installer(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    install_function: DI_FUNCTION,
) -> io::Result<()> {
    unsafe { SetupDiCallClassInstaller(install_function, devinfo, Some(devinfo_data)) }
        .map_err(error_map)
}

pub fn open_dev_reg_key(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    scope: u32,
    hw_profile: u32,
    key_type: u32,
    sam_desired: u32,
) -> io::Result<HKEY> {
    unsafe {
        SetupDiOpenDevRegKey(
            devinfo,
            devinfo_data,
            scope,
            hw_profile,
            key_type,
            sam_desired,
        )
    }
    .map_err(error_map)
}

pub fn notify_change_key_value(
    key: HKEY,
    watch_subtree: bool,
    notify_filter: REG_NOTIFY_FILTER,
    milliseconds: u32,
) -> io::Result<()> {
    let event = unsafe { CreateEventW(None, false, false, None) }.map_err(error_map)?;

    let result =
        unsafe { RegNotifyChangeKeyValue(key, watch_subtree, notify_filter, Some(event), true) };
    winapi_result(result)?;

    match unsafe { WaitForSingleObject(event, milliseconds) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Registry timed out",
        )),
        _ => Err(io::Error::last_os_error()),
    }
}

pub fn enum_driver_info(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    driver_type: SETUP_DI_DRIVER_TYPE,
    member_index: u32,
) -> Option<io::Result<SP_DRVINFO_DATA_V2_W>> {
    let mut drvinfo_data: SP_DRVINFO_DATA_V2_W = unsafe { mem::zeroed() };
    drvinfo_data.cbSize = mem::size_of_val(&drvinfo_data) as _;
    match unsafe {
        SetupDiEnumDriverInfoW(
            devinfo,
            Some(devinfo_data),
            driver_type,
            member_index,
            &mut drvinfo_data,
        )
    } {
        Err(err) if err.code() == ERROR_NO_MORE_ITEMS.to_hresult() => None,
        Err(err) => Some(Err(error_map(err))),
        Ok(()) => Some(Ok(drvinfo_data)),
    }
}

pub fn enum_device_info(
    devinfo: HDEVINFO,
    member_index: u32,
) -> Option<io::Result<SP_DEVINFO_DATA>> {
    let mut devinfo_data: SP_DEVINFO_DATA = unsafe { mem::zeroed() };
    devinfo_data.cbSize = mem::size_of_val(&devinfo_data) as _;

    match unsafe { SetupDiEnumDeviceInfo(devinfo, member_index, &mut devinfo_data) } {
        Err(err) if err.code() == ERROR_NO_MORE_ITEMS.to_hresult() => None,
        Err(err) => Some(Err(error_map(err))),
        Ok(()) => Some(Ok(devinfo_data)),
    }
}

pub fn get_device_name(devinfo: HDEVINFO, devinfo_data: &SP_DEVINFO_DATA) -> io::Result<String> {
    let mut prop_type = unsafe { mem::zeroed() };
    let mut required_size: u32 = 0;
    match unsafe {
        SetupDiGetDevicePropertyW(
            devinfo,
            devinfo_data,
            &DEVPKEY_Wintun_Name,
            &mut prop_type,
            None,
            Some(&mut required_size),
            0,
        )
    } {
        Ok(_) => (),
        Err(err) => {
            if err.code() != ERROR_INSUFFICIENT_BUFFER.to_hresult() {
                return Err(error_map(err));
            }
        }
    }

    let mut buf: Vec<u8> = vec![0; required_size as usize];

    unsafe {
        SetupDiGetDevicePropertyW(
            devinfo,
            devinfo_data,
            &DEVPKEY_Wintun_Name,
            &mut prop_type,
            Some(buf.as_mut_slice()),
            Some(&mut required_size),
            0,
        )
    }
    .map_err(error_map)?;

    Ok(decode_utf8(&buf))
}

pub fn device_io_control(
    handle: HANDLE,
    io_control_code: u32,
    in_buffer: &impl Copy,
    out_buffer: &mut impl Copy,
) -> io::Result<()> {
    unsafe {
        DeviceIoControl(
            handle,
            io_control_code,
            Some(in_buffer as *const _ as _),
            mem::size_of_val(in_buffer) as _,
            Some(out_buffer as *mut _ as _),
            mem::size_of_val(out_buffer) as _,
            None,
            None,
        )
    }
    .map_err(error_map)
}

pub fn get_mtu_by_index(index: u32, is_v4: bool) -> io::Result<u32> {
    // https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipinterfacetable#examples
    let mut if_table: *mut MIB_IPINTERFACE_TABLE = ptr::null_mut();
    let mut mtu = None;
    unsafe {
        let result = GetIpInterfaceTable(if is_v4 { AF_INET } else { AF_INET6 }, &mut if_table);
        winapi_result(result)?;

        let ifaces = std::slice::from_raw_parts::<MIB_IPINTERFACE_ROW>(
            &(*if_table).Table[0],
            (*if_table).NumEntries as usize,
        );
        for x in ifaces {
            if x.InterfaceIndex == index {
                mtu = Some(x.NlMtu);
                break;
            }
        }
        FreeMibTable(if_table as _);
    }
    if let Some(mtu) = mtu {
        Ok(mtu)
    } else {
        Err(io::Error::from(io::ErrorKind::NotFound))
    }
}

pub fn set_interface_name(luid: NET_LUID_LH, name: &str) -> io::Result<()> {
    let guid = luid_to_guid(&luid)?;

    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok()?;

        CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        )
        .map_err(error_map)?;

        defer! {
            CoUninitialize();
        };

        const CLSID_CONNECTION_MANAGER: GUID =
            GUID::from_u128(0xba126ad1_2166_11d1_b1d0_00805fc1270e);
        let manager: INetConnectionManager =
            CoCreateInstance(&CLSID_CONNECTION_MANAGER, None, CLSCTX_ALL).map_err(error_map)?;

        let enum_conn = manager.EnumConnections(NCME_DEFAULT).map_err(error_map)?;

        let mut fetched_count: u32 = 0;
        let mut connection_array: [Option<INetConnection>; 64] = std::array::from_fn(|_| None);

        enum_conn
            .Next(&mut connection_array, &mut fetched_count)
            .map_err(error_map)?;
        for conn in connection_array.into_iter().flatten() {
            if let Ok(props) = conn.GetProperties() {
                if (*props).guidId == guid {
                    conn.Rename(&windows::core::HSTRING::from(name))
                        .map_err(error_map)?;
                    break;
                }
            }
        }
    }
    Ok(())
}

pub fn set_interface_metric(index: u32, metric: u32) -> io::Result<()> {
    for family in &[AF_INET, AF_INET6] {
        let mut row = MIB_IPINTERFACE_ROW::default();
        row.Family = *family;
        row.InterfaceIndex = index;

        let result = unsafe { GetIpInterfaceEntry(&mut row) };
        winapi_result(result)?;

        row.Metric = metric;
        row.UseAutomaticMetric = false;

        let result = unsafe { SetIpInterfaceEntry(&mut row as _) };
        winapi_result(result)?;
    }

    Ok(())
}

pub fn set_interface_mtu(luid: NET_LUID_LH, mtu: u32, is_v4: bool) -> io::Result<()> {
    let mut row: MIB_IPINTERFACE_ROW = MIB_IPINTERFACE_ROW::default();
    row.Family = if is_v4 { AF_INET } else { AF_INET6 };
    row.InterfaceLuid = luid;

    let result = unsafe { GetIpInterfaceEntry(&mut row) };
    winapi_result(result)?;

    row.NlMtu = mtu;
    row.SitePrefixLength = 0;

    let result = unsafe { SetIpInterfaceEntry(&mut row as _) };
    winapi_result(result)
}

pub fn addresses(index: u32) -> io::Result<Vec<IpAddr>> {
    let mut if_table: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
    let result = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut if_table) };
    winapi_result(result)?;

    let table = unsafe { if_table.as_ref().unwrap() };
    let address_set: Vec<IpAddr> =
        unsafe { slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as _) }
            .iter()
            .filter(|row| row.InterfaceIndex == index)
            .map(|row| convert_sockaddr(row.Address).ip())
            .collect();

    unsafe {
        FreeMibTable(if_table as _);
    }

    Ok(address_set)
}

pub fn add_address(
    index: u32,
    address: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
) -> io::Result<()> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut row as _) };

    row.InterfaceIndex = index;
    row.Address = SocketAddr::new(address, 0).into();
    row.OnLinkPrefixLength = prefix;

    let result = unsafe { CreateUnicastIpAddressEntry(&row) };
    if result != ERROR_OBJECT_ALREADY_EXISTS {
        winapi_result(result)?;
    }

    if let Some(gateway) = gateway {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row as _) };

        row.InterfaceIndex = index;
        row.NextHop = SocketAddr::new(gateway, 0).into();
        row.Metric = 0;
        row.Protocol = MIB_IPPROTO_NETMGMT;
        row.Origin = NlroManual;

        let result = unsafe { CreateIpForwardEntry2(&row) };
        if result != ERROR_OBJECT_ALREADY_EXISTS {
            winapi_result(result)?;
        }
    }

    Ok(())
}

pub fn remove_address(index: u32, address: IpAddr) -> io::Result<()> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut row as _) };

    row.InterfaceIndex = index;
    row.Address = SocketAddr::new(address, 0).into();

    let result = unsafe { DeleteUnicastIpAddressEntry(&row) };
    winapi_result(result)
}
