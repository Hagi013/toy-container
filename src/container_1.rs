use anyhow::Result;
use std::io::{Write, Stderr};
use std::process::{Command, Stdio};
use std::fs::{self, copy, read_dir, FileType, set_permissions};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::thread::sleep;
use nix::sched::{self, CloneFlags};
use nix::unistd::{Pid, getpid, sethostname, chroot, chdir, mkdir};
use nix::sys::stat::Mode;
use nix::mount::{mount, MsFlags};
use std::time::Duration;
use std::path::Path;
use std::ffi::OsStr;

fn main() -> Result<()> {
    let cb = Box::new(|| {
        let self_pid = getpid();
        sethostname("container").unwrap();
        mount::<str, str, str, str>(
            Some("proc"),
            "/root/chroot/proc",
            Some("proc"),
            MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            None
        ).unwrap();
        exec_sh("ipcs", self_pid);
        exec_sh("ip addr show", self_pid);
        exec_sh("id", self_pid);
        chroot::<str>("/root/chroot").unwrap();
        loop {
            sleep(Duration::from_secs(3));
            spawn_sh("id", self_pid);
            spawn_sh("ipcs", self_pid);
            spawn_sh("ip addr show", self_pid);
            spawn_sh("ps -aufxw", self_pid);
            spawn_sh("hostname", self_pid);
            spawn_sh("pwd", self_pid);
            spawn_sh("uname -n", self_pid);
            // spawn_sh("ls -asl /proc", self_pid);
            spawn_sh("pwd", self_pid);
            // spawn_sh("ls -a ..", self_pid);
        }
        return 0 as isize;
    });
    prepare_bash();
    let mut stack = vec![0u8; 1024 * 1024];
    // ref: https://github.com/nix-rust/nix/issues/343
    let pid = sched::clone(cb,
                           stack.as_mut_slice(),
                           CloneFlags::CLONE_NEWIPC | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS,
                           None,
    ).unwrap();
    println!("pid: {:?}", pid);
    let root_pid = getpid();
    update_mapping(Mapping::UID, pid, "0 0 1\n");
    update_mapping(Mapping::GID, pid, "0 0 1\n");
    loop {
        exec_sh("uname -n", root_pid);
        sleep(Duration::from_secs(3));
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

fn spawn_sh(command: &str, pid: Pid) {
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
    mkdir::<str>("/root/chroot", Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO)?;
    // set_permissions("/root/chroot", PermissionsExt::from_mode(0o777));
    mkdir::<str>("/root/chroot/proc", Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO)?;
    mkdir::<str>("/root/chroot/bin", Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO)?;
    mkdir::<str>("/root/chroot/lib", Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO)?;
    mkdir::<str>("/root/chroot/lib64", Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO)?;
    mkdir::<str>("/root/chroot/usr", Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO)?;

    copy_dir("/bin/", "/root/chroot/bin/")?;
    copy_dir("/lib/", "/root/chroot/lib/")?;
    copy_dir("/lib64/", "/root/chroot/lib64/")?;
    copy_dir("/usr/", "/root/chroot/usr/")?;
    chdir::<str>("/root/chroot/")?;
    Ok(())
}

fn copy_dir(path: &str, target: &str) -> Result<()> {
    let path = Path::new(path);
    // println!("{:?}, {:?}", path, path.is_dir());
    if !path.is_dir() {
        // println!("{:?}, {:?}, {:?}", path.as_os_str(), path.is_file(), Path::new(target).join(path.file_name().unwrap()).as_os_str());
        copy(path.as_os_str(), Path::new(target).join(path.file_name().unwrap()).as_os_str()).unwrap();
        return Ok(());
    }
    for r in read_dir(path).unwrap() {
        let dir_entry = r.unwrap();
        // println!("in iterator {:?}, {:?}", dir_entry, dir_entry.path());
        let entry = dir_entry.path();
        if entry.is_dir() {
            // println!("recursively. {:?}, {:?}", entry.as_os_str().to_str().unwrap(), Path::new(target).join(entry.file_name().unwrap()).as_os_str().to_str().unwrap());
            mkdir::<OsStr>(Path::new(target).join(entry.file_name().unwrap()).as_os_str(), Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO).unwrap();
            copy_dir(entry.as_os_str().to_str().unwrap(), Path::new(target).join(entry.file_name().unwrap()).as_os_str().to_str().unwrap());
        } else {
            // println!("this is file. {:?}, {:?}, {:?}", entry.as_os_str(), Path::new(target).join(entry.file_name().unwrap()).as_os_str(), entry.metadata());
            if entry.file_name().unwrap().to_str().unwrap() != "README.Bugs" {
                // println!("this is file. {:?}, {:?}", entry.as_os_str(), Path::new(target).join(entry.file_name().unwrap()).as_os_str());
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
