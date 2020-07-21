use anyhow::{Result, Error};
use std::io::{Write, Stderr, BufReader, BufRead, Read, BufWriter};
use std::process::{Command, Stdio};
use std::fs::{self, copy, read_dir, FileType, set_permissions, remove_dir, OpenOptions, File};
use std::os::unix::fs::{symlink, PermissionsExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::thread::sleep;
use nix::sched::{self, CloneFlags};
use nix::unistd::{Pid, getpid, sethostname, chroot, chdir, mkdir, pivot_root};
use nix::sys::stat::Mode;
use nix::mount::{mount, MsFlags, umount2, MntFlags};
use nix::sys::wait::WaitStatus;
use nix::sys::signal;
use nix::libc::{self, user_regs_struct};
use std::time::Duration;
use std::path::{Path, PathBuf};
use std::ffi::OsStr;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard, Arc};
use std::collections::HashMap;
use std::io::stdout;

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
    let prepare_file = make_file("prepare.txt")?;
    let command_start_check_pipe: Arc<RwLock<PathBuf>> = Arc::new(RwLock::new(prepare_file));

    let cb = Box::new(|| {
        // let command_start_flag = Arc::clone(&command_start_flag);
        let command_start_check_pipe = Arc::clone(&command_start_check_pipe);
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

        // sleep(Duration::from_secs(1));
        if (*MOUNT_DIR.read().unwrap()).is_some() {
            chdir("/target").unwrap();
            spawn_sh("ls -a /tmp", self_pid);
            {
                let read_guard = command_start_check_pipe.read().unwrap();
                let mut file = OpenOptions::new()
                    .write(true)
                    .open((*read_guard).as_path()).unwrap();
                file.write_all(b"Prepare done!").unwrap();
            }
            println!("Init *command_start_check_pipe");
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
    // ptrace::set_emulate_option(pid);

    let root_pid = getpid();
    update_mapping(Mapping::UID, pid, "0 0 1\n");
    update_mapping(Mapping::GID, pid, "0 0 1\n");

    let mut prev_orig_rax_by_pid: HashMap<Pid, u64> = HashMap::new();
    let mut emulate_flag = false;
    let command_start_check_pipe = Arc::clone(&command_start_check_pipe);
    let mut prepare_flag = false;
    loop {
        // let status: WaitStatus = ptrace::wait_pid(pid).unwrap();
        let status: WaitStatus = ptrace::wait_all().unwrap();
        let pid = status.pid().unwrap();
        // println!("pid: {:?}", pid);
        // let pid_num: i64 = ptrace::get_event(pid)?;
        // println!("pid: {:?}, get_event: {:?}", pid, pid_num);

        let prev_orig_rax = match prev_orig_rax_by_pid.get(&pid) {
            Some(rax) => rax.to_owned(),
            None => 0,
        };

        // println!("status: {:?}", status);
        let mut regs: user_regs_struct = ptrace::getregs(pid).unwrap();
        // println!("prev_orig_rax: {:?}, orig_rax: {:?}, rsi: {:?}, rdx: {:?}, rdi: {:?}, rax: {:?}", prev_orig_rax, regs.orig_rax, regs.rsi, regs.rdx, regs.rdi, regs.rax);

        if !prepare_flag {
            {
                let read_guard = command_start_check_pipe.read().unwrap();
                let mut contents = fs::read_to_string(read_guard.as_path()).unwrap();
                // println!("command_start_check_pipe: {:?}", contents);
                if contents == "Prepare done!".to_owned() {
                    println!("Prepare done!!!!!!!!!!!!");
                    prepare_flag = true;
                    emulate_flag = match handle_syscall(pid, status, regs, prev_orig_rax, root_pid) {
                        Ok(flag) => {
                            if flag.is_none() { break; }
                            flag.unwrap()
                        },
                        Err(e) => {
                            println!("Error!!!: {:?}", e);
                            break
                        },
                    }
                }
            }
        } else {
            emulate_flag = match handle_syscall(pid, status, regs, prev_orig_rax, root_pid) {
                Ok(flag) => {
                    if flag.is_none() { break; }
                    flag.unwrap()
                },
                Err(e) => {
                    println!("Error!!!: {:?}", e);
                    break
                },
            }
        }

        // prev_orig_rax = regs.orig_rax;
        prev_orig_rax_by_pid.insert(pid, regs.orig_rax);
        // println!("");
        if emulate_flag {
            if regs.eflags & 1 << 8 != 0 {
                println!("sysemu_single!!!!!");
                ptrace::sysemu_single(pid);
            } else {
                ptrace::sysemu(pid);
            }
            println!("Emulate!!!!!");
            // ptrace::syscall(pid);
            println!("Exit!!!!! prev_orig_rax: {:?}, orig_rax: {:?}, rsi: {:?}, rdx: {:?}, rdi: {:?}, rax: {:?}", prev_orig_rax, regs.orig_rax, regs.rsi, regs.rdx, regs.rdi, regs.rax);
        } else {
            if regs.eflags & 1 << 8 != 0 {
                ptrace::syscall_step(pid);
            } else {
                ptrace::syscall(pid);
            }
            ptrace::wait_pid(pid).unwrap();
            let mut regs: user_regs_struct = ptrace::getregs(pid).unwrap();
            // println!("syscall Exit!!!!! prev_orig_rax: {:?}, orig_rax: {:?}, rsi: {:?}, rdx: {:?}, rdi: {:?}, rax: {:?}", prev_orig_rax, regs.orig_rax, regs.rsi, regs.rdx, regs.rdi, regs.rax);
            ptrace::syscall(pid);
        }
        emulate_flag = false;
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
    println!("pid: {:?}, Status: {:?}, command: {:?}", getpid(), output.status, command);
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

fn make_fifo(file_path: &str, mode: Mode) -> Result<PathBuf> {
    let fifo_path = Path::new("/tmp").join(file_path);
    nix::unistd::mkfifo(&fifo_path, mode)?;
    Ok(fifo_path)
}

fn make_file(path: &str) -> Result<PathBuf> {
    let file_path = Path::new("/tmp").join(path);
    fs::write(&file_path, "")?;
    Ok(file_path)
}

fn handle_syscall(pid: Pid, status: WaitStatus, regs: user_regs_struct, prev_orig_rax: u64, root_pid: Pid) -> Result<Option<bool>> {
    match status {
        WaitStatus::Stopped(pid, sig) => {
            match sig {
                signal::SIGCHLD => {
                    let siginfo: libc::siginfo_t = ptrace::get_siginfo(pid).unwrap();
                    println!("siginfo: {:?}, si_value: {:?}, si_addr: {:?}", siginfo, unsafe { siginfo.si_value() }, unsafe { siginfo.si_addr() });
                    ptrace::syscall_step(pid);
                },
                signal::SIGSEGV => {
                    ptrace::detach(pid);
                    println!("Pid: {:?} is Segv.", pid);
                    println!("orig_rax: {:?}, rsi: {:?}, rdx: {:?}, rdi: {:?}, rax: {:?}", regs.orig_rax, regs.rsi, regs.rdx, regs.rdi, regs.rax);
                    if regs.orig_rax as i64 != -1 {
                        return Ok(None)
                    }
                }
                _ => {
                    println!("nothing.(not PtraceSyscall)");
                    return Ok(Some(false))
                }
            }
        },
        WaitStatus::PtraceSyscall(pid) => {
            if regs.orig_rax == libc::SYS_write as u64 && (regs.rdi == 1 || regs.rdi == 2 ) {
                let mut bytes_list = vec![];
                println!("Enter!! orig_rax: {:?}, rsi: {:?}, rdx: {:?}, rdi: {:?}, rax: {:?}", regs.orig_rax, regs.rsi, regs.rdx, regs.rdi, regs.rax);
                let size_by_byte = if (regs.rdx % (std::mem::size_of::<u64>() as u64)) == 0 {
                    (regs.rdx / (std::mem::size_of::<u64>() as u64))
                } else {
                    (regs.rdx / (std::mem::size_of::<u64>() as u64)) + 1
                };
                // println!("size: {}", size_by_byte);
                for i in 0..size_by_byte {
                    let data = ptrace::read_memory(pid, regs.rsi + (i * 8))?;
                    for j in 0..8 {
                        if i == size_by_byte - 1 && j as i64 > (regs.rdx as i64 % (std::mem::size_of::<i64>() as i64) - 1) { break; }
                        bytes_list.push((data >> j * 8) as u8);
                    }
                    // print!("{:?}", std::str::from_utf8(&bytes_list).unwrap());
                    stdout().write_all(&bytes_list.as_slice()).map_err(|e| Error::new(e))?;
                    stdout().flush().map_err(|e| Error::new(e))?;
                    bytes_list = vec![];
                }
                let mut new_regs = regs.clone();
                new_regs.rax = regs.rdx;
                ptrace::setregs(pid, new_regs);
                return Ok(Some(true))
            }

            // なぜかpipeが失敗するので、無理やり成功させた異にする
            if regs.orig_rax == libc::SYS_pipe as u64 {
                let mut new_regs = regs.clone();
                new_regs.rax = 0;
                ptrace::setregs(pid, new_regs);
                return Ok(Some(false))
            }
        },
        _ => {
            println!("nothing.(not stopped)");
            return Ok(Some(false))
        },
    }
    Ok(Some(false))
}