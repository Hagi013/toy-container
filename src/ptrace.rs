use anyhow::Result;
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use nix::libc::user_regs_struct;

pub fn attach(pid: Pid) -> Result<()> {
    ptrace::attach(pid)?;
    Ok(())
}

pub fn wait_pid(pid: Pid) -> Result<WaitStatus> {
    let status = waitpid(pid, None)?;
    Ok(status)
}

pub fn syscall(pid: Pid) {
    ptrace::syscall(pid, None);
}

pub fn getregs(pid: Pid) -> Result<user_regs_struct> {
    Ok(ptrace::getregs(pid)?)
}