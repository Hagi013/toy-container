use anyhow::Result;
use std::io::{Write, Stderr, BufReader, BufRead};
use std::process::{Command, Stdio};
use std::fs::{self, copy, read_dir, FileType, set_permissions, remove_dir};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::thread::sleep;
use nix::sched::{self, CloneFlags};
use nix::unistd::{Pid, getpid, sethostname, chroot, chdir, mkdir, pivot_root};
use nix::sys::stat::Mode;
use nix::mount::{mount, MsFlags, umount2, MntFlags};
use nix::sys::wait::WaitStatus;
use nix::sys::signal;
use nix::libc::{self, user_regs_struct};
use std::time::Duration;
use std::path::Path;
use std::ffi::OsStr;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

mod ptrace;

#[macro_use]
extern crate lazy_static;

static MOUNT_POINT: &str = "/root/rootfs";

lazy_static! {
    #[derive(Debug)]
    static ref COMMAND: RwLock<String> = RwLock::new("echo Hello Rust World!!".to_string());
    #[derive(Debug)]
    static ref MOUNT_DIR: RwLock<Option<String>> = RwLock::new(None);
}

fn main() -> Result<()> {
    let commands: Vec<String> = std::env::args().collect();
    if commands.len() < 2 {
        println!("You should input command.");
        std::process::exit(0);
    }
    let command = &commands[1];
    {
        let mut write_guard: RwLockWriteGuard<String> = COMMAND.write().unwrap();
        *write_guard = command.to_owned();
    }
    println!("command: {:?}", *COMMAND.read().unwrap());

    if commands.len() > 2 {
        let mount_dir: &str = &commands[2];
        {
            let mut write_guard: RwLockWriteGuard<Option<String>> = MOUNT_DIR.write().unwrap();
            *write_guard = Some(mount_dir.to_owned());
        }
        println!("mount_dir: {:?}", *MOUNT_DIR.read().unwrap());
    }

    let cb = Box::new(|| {
        let self_pid = getpid();
        sethostname("container").unwrap();
        mount::<str, str, str, str>(
            Some("proc"),
            &format!("{}/{}", MOUNT_POINT, "proc"),
            Some("proc"),
            MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            None
        ).unwrap();
        chdir("/root");
        mount::<str, str, str, str>(
            Some("rootfs"),
            &MOUNT_POINT,
            None,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None
        ).unwrap();

        mount::<str, str, str, str>(
            Some("/tmp"),
            &format!("{}/{}", MOUNT_POINT, "tmp"),
            None,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None
        ).unwrap();

        mount::<str, str, str, str>(
            Some("/dev"),
            &format!("{}/{}", MOUNT_POINT, "dev"),
            None,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None
        ).unwrap();

        mount::<str, str, str, str>(
            Some("/sys"),
            &format!("{}/{}", MOUNT_POINT, "sys"),
            None,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None
        ).unwrap();

        mkdir::<str>(&format!("{}/{}", MOUNT_POINT, "oldrootfs"), Mode::S_IRWXU).unwrap();

        exec_sh("ip addr show", self_pid);
        if (*MOUNT_DIR.read().unwrap()).is_some() {
            mount_dir(&(&*MOUNT_DIR.read().unwrap()).as_ref().unwrap(), "target");
        }

        pivot_root::<str, str>("rootfs", &format!("{}/{}", MOUNT_POINT, "oldrootfs")).unwrap();
        umount2::<str>("/oldrootfs", MntFlags::MNT_DETACH).unwrap();
        remove_dir("/oldrootfs").unwrap();
        chdir("/").unwrap();

        if (*MOUNT_DIR.read().unwrap()).is_some() {
            chdir("/target").unwrap();
            spawn_sh("ls -a", self_pid);
            spawn_sh(&*COMMAND.read().unwrap(), self_pid);
        }
        loop {
            // sleep(Duration::from_secs(3));
            // spawn_sh("ls -a", self_pid);
        }
        return 0 as isize;
    });
    prepare_bash();
    let mut stack = vec![0u8; 1024 * 1024 * 1024 * 1024];
    // ref: https://github.com/nix-rust/nix/issues/343
    let pid = sched::clone(cb,
                           stack.as_mut_slice(),
                           CloneFlags::CLONE_NEWIPC | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS,
                           None,
    ).unwrap();

    println!("pid: {:?}", pid);
    ptrace::attach(pid).unwrap();
    ptrace::set_tracesysgood(pid);

    let root_pid = getpid();
    update_mapping(Mapping::UID, pid, "0 0 1\n");
    update_mapping(Mapping::GID, pid, "0 0 1\n");
    let mut is_enter_stop: bool = false;
    let mut prev_orig_rax = 0;
    let mut emu_flag: bool = false;
    loop {
        let status: WaitStatus = ptrace::wait_pid(pid).unwrap();
        println!("status: {:?}", status);
        let regs: user_regs_struct = ptrace::getregs(pid).unwrap();
        println!("emulate: {:?}, prev_orig_rax: {:?}, orig_rax: {:?}, rsi: {:?}, rdx: {:?}, rdi: {:?}, rax: {:?}", emu_flag, prev_orig_rax, regs.orig_rax, regs.rsi, regs.rdx, regs.rdi, regs.rax);
        match status {
            WaitStatus::Stopped(pid, sig) => {
                match sig {
                    signal::SIGTRAP => {
                        is_enter_stop = if regs.orig_rax != prev_orig_rax {
                            true
                        } else if emu_flag && regs.orig_rax == prev_orig_rax {
                            true
                        } else {
                            false
                        };
                        if regs.orig_rax == libc::SYS_write as u64 && (regs.rdi == 1 || regs.rdi == 2 ) {
                            println!("regs.orig_rax == libc::SYS_write, emulate: {:?}, prev_orig_rax: {:?}, orig_rax: {:?}, rsi: {:?}, rdx: {:?}, rdi: {:?}, rax: {:?}", emu_flag, prev_orig_rax, regs.orig_rax, regs.rsi, regs.rdx, regs.rdi, regs.rax);
                            let mut bytes_list = vec![];
                            if is_enter_stop {
                                for i in 0..(regs.rdx / (std::mem::size_of::<u64>() as u64)) {
                                    let data = ptrace::read_memory(pid, regs.rsi + (i * 8))?;
                                    for j in 0..8 {
                                        bytes_list.push((data >> j * 8) as u8);
                                    }
                                    print!("{:?}", std::str::from_utf8(&bytes_list).unwrap());
                                    bytes_list = vec![];
                                    emu_flag = true;
                                }
                            } else {
                                emu_flag = false;
                            }
                            println!("");
                        } else {
                            emu_flag = false;
                        }
                    },
                    _ => {
                        println!("nothing.(not trap)");
                        emu_flag = false;
                    }
                }
            },
            _ => {
                println!("nothing.(not stopped)");
                emu_flag = false;
            },
        }
        is_enter_stop = false;
        prev_orig_rax = regs.orig_rax;
        if emu_flag {
            println!("emulate.{:?}", emu_flag);
            // ptrace::sysemu(pid);
            // ptrace::sysemu_single(pid);
            ptrace::syscall(pid);
        } else {
            ptrace::syscall(pid);
        }
        // emu_flag = false;
        // sleep(Duration::from_secs(3));
    }
    Ok(())
}

fn exec_sh(command: &str, pid: Pid) {
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .output()
        .unwrap();
    let stdout = output.stdout;
    let lines = String::from_utf8(stdout).unwrap();
    let split_by_line: Vec<&str> = lines.split('\n').collect();
    for &line in split_by_line.iter() {
        println!("{}({:?}): {:?}", command, pid, line);
    }
}

pub fn spawn_sh(command: &str, pid: Pid) {
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();
    println!("Status: {:?}, command: {:?}", output.status, command);
    let stdout = output.stdout;
    let lines = String::from_utf8(stdout).unwrap();
    let split_by_line: Vec<&str> = lines.split('\n').collect();
    for &line in split_by_line.iter() {
        println!("{:?}({:?}): {:?}", command, pid, line);
    }
}

enum Mapping {
    UID, GID,
}
fn update_mapping(mapping: Mapping, pid: Pid, content: &str) {
    let map_file = match mapping {
        Mapping::UID => "uid_map",
        Mapping::GID => "gid_map",
    };
    fs::OpenOptions::new()
        .write(true)
        .open(format!("/proc/{}/{}", pid.as_raw() as i32, map_file))
        .and_then(|mut f| f.write(content.as_bytes()))
        .unwrap_or_else(|e| panic!("could not write gid map: {}", e));
}

fn prepare_bash() -> Result<()> {
    mkdir::<str>(&MOUNT_POINT, Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO).unwrap();
    // mkdir::<str>(&format!("{:?}/{:?}", MOUNT_POINT, oldrootfs), Mode::S_IRWXU).unwrap();
    // set_permissions("/root/chroot", PermissionsExt::from_mode(0o777));
    // println!("{:?}", format!("{}/{}", MOUNT_POINT, "proc"));
    mkdir::<str>(&format!("{}/{}", MOUNT_POINT, "proc"), Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO)?;
    mkdir::<str>(&format!("{}/{}", MOUNT_POINT, "bin"), Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO)?;
    mkdir::<str>(&format!("{}/{}", MOUNT_POINT, "lib"), Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO)?;
    mkdir::<str>(&format!("{}/{}", MOUNT_POINT, "lib64"), Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO)?;
    mkdir::<str>(&format!("{}/{}", MOUNT_POINT, "usr"), Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO)?;
    mkdir::<str>(&format!("{}/{}", MOUNT_POINT, "tmp"), Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO)?;
    mkdir::<str>(&format!("{}/{}", MOUNT_POINT, "dev"), Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO)?;
    mkdir::<str>(&format!("{}/{}", MOUNT_POINT, "sys"), Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO)?;

    copy_dir("/bin/", &format!("{}/{}", MOUNT_POINT, "bin"))?;
    copy_dir("/lib/", &format!("{}/{}", MOUNT_POINT, "lib"))?;
    copy_dir("/lib64/", &format!("{}/{}", MOUNT_POINT, "lib64"))?;
    copy_dir("/usr/", &format!("{}/{}", MOUNT_POINT, "usr"))?;
    Ok(())
}

fn copy_dir(path: &str, target: &str) -> Result<()> {
    let path = Path::new(path);
    if !path.is_dir() {
        copy(path.as_os_str(), Path::new(target).join(path.file_name().unwrap()).as_os_str()).unwrap();
        return Ok(());
    }
    for r in read_dir(path).unwrap() {
        let dir_entry = r.unwrap();
        let entry = dir_entry.path();
        if entry.is_dir() {
            mkdir::<OsStr>(Path::new(target).join(entry.file_name().unwrap()).as_os_str(), Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO).unwrap();
            copy_dir(entry.as_os_str().to_str().unwrap(), Path::new(target).join(entry.file_name().unwrap()).as_os_str().to_str().unwrap());
        } else {
            if entry.file_name().unwrap().to_str().unwrap() != "README.Bugs" {
                copy(entry.as_os_str(), Path::new(target).join(entry.file_name().unwrap()).as_os_str()).unwrap();
            }
        }
    }
    Ok(())
}

fn dir(path: &str) {
    for r in read_dir(path).unwrap() {
        let dir_entry = r.unwrap();
        println!("in iterator {:?}, {:?}", dir_entry, dir_entry.path());
    }
}

fn mount_dir(source: &str, target: &str) -> Result<()> {
    let source_path = Path::new(source);
    if !source_path.exists() {
        println!("mount source is not existing.({:?})", source);
        return Ok(());
    }
    let target_path = Path::new(MOUNT_POINT).join(target);
    mkdir::<Path>(target_path.as_path(), Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO).unwrap();
    mount::<Path, Path, str, str>(
        Some(source_path),
        target_path.as_path(),
        Some("ext4"),
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None,
    );
    Ok(())
}
