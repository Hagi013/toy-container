use anyhow::Result;
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use nix::libc::{self, user_regs_struct};
use nix::errno::Errno;

pub fn attach(pid: Pid) -> Result<()> {
    ptrace::attach(pid)?;
    Ok(())
}

pub fn detach(pid: Pid) -> Result<()> {
    ptrace::detach(pid, None)?;
    Ok(())
}

pub fn set_tracesysgood(pid: Pid) {
    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD);
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

pub fn setregs(pid: Pid, urs: user_regs_struct) -> Result<()> {
    Ok(ptrace::setregs(pid, urs)?)
}

pub fn read_memory(pid: Pid, addr: u64) -> Result<i64> {
    let res = ptrace::read(pid, addr as *mut std::ffi::c_void)?;
    Ok(res as i64)
}

pub fn sysemu(pid: Pid) -> Result<()> {
    Errno::result(
        unsafe { libc::ptrace(31 as libc::c_uint, libc::pid_t::from(pid), std::ptr::null_mut::<libc::c_uint>(), std::ptr::null_mut::<libc::c_uint>()) }
        // unsafe { libc::ptrace(24 as libc::c_uint, libc::pid_t::from(pid) as i32, std::ptr::null_mut::<std::ffi::c_void>(), std::ptr::null_mut::<std::ffi::c_void>()) }
    )
        .map(drop);
    Ok(())
}

pub fn sysemu_single(pid: Pid) -> Result<()> {
    Errno::result(
        unsafe { libc::ptrace(32 as libc::c_uint, libc::pid_t::from(pid), std::ptr::null_mut::<libc::c_uint>(), std::ptr::null_mut::<libc::c_uint>()) }
    )
        .map(drop);
    Ok(())

}
