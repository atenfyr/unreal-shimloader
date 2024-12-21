#![allow(unused, clippy::undocumented_unsafe_blocks)]
#![warn(
    clippy::pedantic,
    clippy::unwrap_used,
)]

use std::{env, thread, fs};
use std::io::Write;
use std::alloc::GlobalAlloc;
use std::collections::HashMap;
use std::ffi::c_void;
use std::fs::{canonicalize, File};
use std::ops::Index;
use std::path::{Path, PathBuf};
use std::os::windows::process::CommandExt;

use chrono::Local;
use log::{debug, error, LevelFilter};
use getargs::{Arg, Opt, Options};
use once_cell::sync::{Lazy, OnceCell};
use utils::NormalizedPath;
use widestring::U16CString;
use windows_sys::w;
use windows_sys::Win32::Foundation::{BOOL, HWND, TRUE};
use windows_sys::Win32::System::Console::AllocConsole;
use windows_sys::Win32::System::Diagnostics::Debug::DebugActiveProcess;
use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessId, CREATE_NO_WINDOW};
use windows_sys::Win32::UI::WindowsAndMessaging::{MESSAGEBOX_STYLE, MessageBoxW};

mod hooks;
mod utils;

static BP_MODS: OnceCell<PathBuf> = OnceCell::new();

static GAME_ROOT: Lazy<PathBuf> = Lazy::new(|| {
    let current_exe = env::current_exe().unwrap();
    current_exe
        .ancestors()
        .nth(3)
        .unwrap_or_else(|| 
            panic!("The executable at {current_exe:?} is not contained within a valid UE directory structure."))
        .to_path_buf()
});

static EXE_DIR: Lazy<PathBuf> = Lazy::new(|| {
    env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
});

static LOCAL_DIR: Lazy<PathBuf> = Lazy::new(|| {
    PathBuf::from(std::env::var("LOCALAPPDATA")
        .expect("No %LOCALAPPDATA% directory"))
        .join("./Astro/Saved/Paks")
});

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    dll_module: u32,
    call_reason: u32,
    reserved: *const c_void
) -> BOOL {
    if call_reason == DLL_PROCESS_ATTACH && BP_MODS.get().is_none() {
        // Initialize the shim if we haven't yet set the TARGET_DIR static.
        // This ensures that DllMain is not called multiple times with DLL_PROCESS_ATTACH.
        shim_init();
    }
    TRUE
}

unsafe fn shim_init() {
    #[cfg(debug_assertions)]
    AllocConsole();

    std::panic::set_hook(Box::new(|x| unsafe {
        let message = format!("unreal-shimloader has crashed: \n\n{x}");
        error!("{message}");

        let message = U16CString::from_str(message);
        MessageBoxW(
            0,
            message.unwrap().as_ptr(),
            w!("unreal-shimloader"),
            0
        );
    }));

    let current_exe = env::current_exe()
        .expect("Failed to get the path of the currently running executable.");
    let exe_dir = current_exe.parent().unwrap();
 
    let mut target = Box::new(File::create(exe_dir.join("shimloader-log.txt")).expect("Failed to create log file."));
    env_logger::Builder::new()
        .target(env_logger::Target::Pipe(target))
        .filter(None, LevelFilter::Debug)
        .format(|buf, record| {
            writeln!(
                buf,
                "[{} {} {}:{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .init();

    debug!("unreal_shimloader -- start");
    debug!("current directory: {exe_dir:?}");
    debug!("current executable: {current_exe:?}");
    debug!("args: {:?}", env::args().collect::<Vec<_>>());

    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut opts = Options::new(args.iter().map(String::as_str));

    let mut pak_dir: Option<PathBuf> = None;

    while let Some(opt) = opts.next_arg().expect("Failed to parse arguments") {
        match opt {
            Arg::Long("pak-dir") => pak_dir = Some(PathBuf::from(opts.value().expect("`--pak-dir` argument has no value."))),
            _ => (),
        }
    }

    let toplevel_dir = current_exe
        .ancestors()
        .nth(3)
        .unwrap_or_else(|| 
            panic!("The executable at {current_exe:?} is not contained within a valid UE directory structure."));

    let integrator_output_path_pbuf = toplevel_dir.join("Content").join("Paks");
    let integrator_output_path = utils::normalize_path(&integrator_output_path_pbuf);
    debug!("integrator_output_path: {integrator_output_path:?}");

    // cleanup old integration, if needed (and swallow any error)
    let _ = fs::remove_file(integrator_output_path.join("999-AstroModIntegrator_P.pak"));

    // If no args are specified then we start the game with mods disabled.
    let run_vanilla = ![&pak_dir].iter().any(|x| x.is_some());
    if run_vanilla {
        // allow game to run normally
        return;
    }
    
    // We derive the local data directory. This is done for two reasons:
    // a) by re-routing the local data directory, we prevent mods loaded classically (e.g. AstroModLoader) from being loaded, meaning shimloader can be used alongside other mod managers
    // b) this allows us to remove the dependency on UE4SS by loading mods directly instead
    // we'll use the LOCALAPPDATA environment variable; this code can be modified later if needed for platforms other than windows
    let local_appdata = std::env::var("LOCALAPPDATA").expect("No %LOCALAPPDATA% directory");
    let local_paks_pbuf = PathBuf::from(local_appdata.clone()).join("Astro/Saved/Paks");
    let local_paks = utils::normalize_path(&local_paks_pbuf);
    debug!("local_paks: {local_paks:?}");

    if !local_paks.is_dir() {
        fs::create_dir_all(&local_paks);
    }

    // Create the bp_mods directory if it doesn't already exist.
    let bp_mods = utils::normalize_path(&pak_dir.unwrap());

    if !bp_mods.is_dir() {
        fs::create_dir_all(&bp_mods);
    }

    // Execute the mod integrator
    run_integrator(&current_exe, &bp_mods, &integrator_output_path);

    // enable hooks
    BP_MODS.set(bp_mods);

    if let Err(e) = hooks::enable_hooks() {
        panic!("Failed to enable one or more hooks. {e}")
    }
}

unsafe fn run_integrator(current_exe: &Path, mods_dir: &Path, integrator_output_path: &Path) {
    let integrator_exe = current_exe.join("../ModIntegrator.exe");
    let paks_dir = current_exe.join("../../../Content/Paks");
    let paks_dir_str = paks_dir.to_str().unwrap();
    let mods_dir_str = mods_dir.to_str().unwrap();
    let integrator_output_path_str = integrator_output_path.to_str().unwrap();
    assert!(integrator_exe.is_file(), "ModIntegrator.exe could not be found at {integrator_exe:?}");

    let outp = std::process::Command::new(integrator_exe).args([mods_dir_str, paks_dir_str, integrator_output_path_str, "../../../"]).creation_flags(CREATE_NO_WINDOW).output().unwrap().stdout;
    debug!("modintegrator says: {}", String::from_utf8(outp).unwrap());
}
