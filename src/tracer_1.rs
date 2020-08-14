use anyhow::{Result, Error};
use std::io::{Write, stdout};
use std::thread::sleep;
use nix::unistd::{Pid, getpid};
use nix::sys::wait::WaitStatus;
use nix::sys::signal;
use nix::libc::{self, user_regs_struct};
use std::time::Duration;
use std::collections::HashMap;

mod ptrace;

fn main() -> Result<()> {
    let commands: Vec<String> = std::env::args().collect();
    if commands.len() < 2 {
        println!("You should input pid.");
        std::process::exit(0);
    }
    let pid_str = &commands[1];
    let pid_num = pid_str.parse::<i64>().unwrap_or(-1);
    if pid_num == -1 { panic!("invalid pid."); }
    let pid = Pid::from_raw(pid_num as libc::pid_t);
    println!("pid: {:?}", pid);

    ptrace::attach(pid).unwrap();
    ptrace::set_emulate_option(pid);

    let root_pid = getpid();
    let mut emulate_flag = false;
    let mut prev_orig_rax_by_pid: HashMap<Pid, u64> = HashMap::new();
    loop {
        let status: WaitStatus = ptrace::wait_all().unwrap();
        let pid = status.pid().unwrap();
        let prev_orig_rax = match prev_orig_rax_by_pid.get(&pid) {
            Some(rax) => rax.to_owned(),
            None => 0,
        };

        println!("status: {:?}", status);
        if check_exited(status) {
            prev_orig_rax_by_pid.remove(&pid).unwrap();
            continue;
        }
        let mut regs: user_regs_struct = ptrace::getregs(pid).unwrap();
        println!("pid: {:?}, prev_orig_rax: {:?}, orig_rax: {:?}, rsi: {:?}, rdx: {:?}, rdi: {:?}, rax: {:?}", pid, prev_orig_rax, regs.orig_rax, regs.rsi, regs.rdx, regs.rdi, regs.rax);
        // cont=0;  while true; do echo hellllo, ${cont}; cont=$((${cont}+1)); sleep 1; done
        // while true; do ps auxf | grep [p]ts/2; sleep 1; done
        emulate_flag = match handle_syscall(pid, status, regs, prev_orig_rax, root_pid) {
            Ok(flag) => {
                if flag.is_none() { break; }
                flag.unwrap()
            },
            Err(e) => {
                println!("Error!!!: {:?}", e);
                break
            },
        };

        prev_orig_rax_by_pid.insert(pid, regs.orig_rax);
        if emulate_flag {
            let mut regs: user_regs_struct = ptrace::getregs(pid).unwrap();
            emulate(pid, regs, prev_orig_rax);
            let end_status = ptrace::wait_pid(pid).unwrap();
            println!("pid: {:?}, end status: {:?}", pid, end_status);
            let mut regs: user_regs_struct = ptrace::getregs(pid).unwrap();
            println!("Emulate!!!!! prev_orig_rax: {:?}, orig_rax: {:?}, rsi: {:?}, rdx: {:?}, rdi: {:?}, rax: {:?}", prev_orig_rax, regs.orig_rax, regs.rsi, regs.rdx, regs.rdi, regs.rax);
            ptrace::syscall(pid);
        } else {
            if regs.eflags & 1 << 8 != 0 {
                ptrace::syscall_step(pid);
            } else {
                ptrace::syscall(pid);
            }
            let end_status = ptrace::wait_pid(pid).unwrap();
            println!("pid: {:?}, end status: {:?}", pid, end_status);
            if check_exited(end_status) {
                prev_orig_rax_by_pid.remove(&pid).unwrap();
                continue;
            }
            let mut regs: user_regs_struct = ptrace::getregs(pid).unwrap();
            println!("syscall Before Exit!!!!! prev_orig_rax: {:?}, orig_rax: {:?}, rsi: {:?}, rdx: {:?}, rdi: {:?}, rax: {:?}", prev_orig_rax, regs.orig_rax, regs.rsi, regs.rdx, regs.rdi, regs.rax);
            handle_syscall_before_exit(pid, end_status, regs);
            ptrace::syscall(pid);
        }
        emulate_flag = false;
        sleep(Duration::from_secs_f32(0.1));
    }
    Ok(())
}

fn handle_syscall(pid: Pid, status: WaitStatus, regs: user_regs_struct, prev_orig_rax: u64, root_pid: Pid) -> Result<Option<bool>> {
    match status {
        WaitStatus::Stopped(pid, sig) => {
            match sig {
                signal::SIGCHLD => {
                    println!("SSSSSSIGCHLD!!!!.");
                    let signal: libc::siginfo_t = fetch_signal(pid).unwrap();
                    let event = ptrace::get_event(pid).unwrap();
                    println!("pid: {:?}, status: {:?}, event: {:?}", pid, status, event);
                    if event != 0 {
                        let event_pid = Pid::from_raw(event as libc::pid_t);
                        ptrace::attach(event_pid);
                        ptrace::set_emulate_option(event_pid);
                    }
                    loop {
                        ptrace::syscall(pid);
                        let status = ptrace::wait_pid(pid).unwrap();
                        let event = ptrace::get_event(pid).unwrap();
                        println!("status!!!!! status: {:?}, event: {:?}", status, event);
                        let regs = ptrace::getregs(pid).unwrap();
                        println!("in handle_syscall. pid: {:?}, prev_orig_rax: {:?}, orig_rax: {:?}, rsi: {:?}, rdx: {:?}, rdi: {:?}, rax: {:?}", pid, prev_orig_rax, regs.orig_rax, regs.rsi, regs.rdx, regs.rdi, regs.rax);
                        if regs.orig_rax == libc::SYS_write as u64 {
                            sleep(Duration::from_secs(3));
                            read_memory(pid, regs.rsi, regs.rdx).unwrap();
                            sleep(Duration::from_secs(3));
                            emulate(pid, regs, prev_orig_rax);
                            sleep(Duration::from_secs(3));
                        }
                        match status {
                            WaitStatus::Stopped(pid, signal::SIGTRAP) => {},
                            _ => break,
                        }
                    }
                },
                signal::SIGSTOP => {
                    println!("Stoppppppp!!!!");
                    let event = ptrace::get_event(pid).unwrap();
                    fetch_signal(pid);
                    println!("pid: {:?}, status: {:?}, event: {:?}", pid, status, event);
                    if event != 0 {
                        let event_pid = Pid::from_raw(event as libc::pid_t);
                        ptrace::attach(event_pid);
                        ptrace::set_emulate_option(event_pid);
                    }
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
                sleep(Duration::from_secs(3));
                read_memory(pid, regs.rsi, regs.rdx).unwrap();
                sleep(Duration::from_secs(3));
                return Ok(Some(true))
            }

            if regs.orig_rax == libc::SYS_read as u64 {
                // read_memory(pid, regs.rsi, regs.rdx).unwrap();
                println!("Read.");
                let mut new_regs = regs.clone();
                new_regs.rax = 0;
                ptrace::setregs(pid, new_regs);
                return Ok(Some(false))
            }

            // なぜかpipeが失敗するので、無理やり成功させた異にする
            if regs.orig_rax == libc::SYS_pipe as u64 {
                let mut new_regs = regs.clone();
                new_regs.rax = 0;
                ptrace::setregs(pid, new_regs);
                return Ok(Some(false))
            }
        },
        WaitStatus::PtraceEvent(p, sig, int) => {
            match sig {
                signal::SIGTRAP => {
                    let siginfo: libc::siginfo_t = ptrace::get_siginfo(p).unwrap();
                    println!("siginfo: {:?}, si_value: {:?}, si_addr: {:?}", siginfo, unsafe { siginfo.si_value() }, unsafe { siginfo.si_addr() });
                    let pid_num: i64 = ptrace::get_event(pid)?;
                    println!("pid: {:?}, get_event: {:?}", pid, pid_num);
                    return Ok(Some(false))
                },
                _ => {
                    println!("Event but not SIGTRAP(status: {:?})", status);
                    return Ok(Some(false))
                }
            }
        },
        _ => {
            println!("nothing.(not stopped)");
            return Ok(Some(false))
        },
    }
    Ok(Some(false))
}

fn handle_syscall_before_exit(pid: Pid, status: WaitStatus, regs: user_regs_struct) {
    match status {
        WaitStatus::PtraceSyscall(pid) => {
            if regs.orig_rax == libc::SYS_wait4 as u64 && regs.rax != 0 && (regs.rax as i64) != -38 {
                let waited_pid = Pid::from_raw(regs.rax as libc::pid_t);
                println!("handle_syscall_before_exit, pid: {:?} is wait4 for {:?}(Status: {:?})", pid, regs.rax, status);
                ptrace::cont(waited_pid);
            }
        },
        _ => {},
    }
}

fn read_memory(pid: Pid, addr: u64, count: u64) -> Result<()> {
    let mut bytes_list = vec![];
    let size_by_byte = if (count % (std::mem::size_of::<u64>() as u64)) == 0 {
        (count / (std::mem::size_of::<u64>() as u64))
    } else {
        (count / (std::mem::size_of::<u64>() as u64)) + 1
    };
    for i in 0..size_by_byte {
        let data = ptrace::read_memory(pid, addr + (i * 8))?;
        for j in 0..8 {
            if i == size_by_byte - 1 && j as i64 > (count as i64 % (std::mem::size_of::<i64>() as i64) - 1) { break; }
            bytes_list.push((data >> j * 8) as u8);
        }
        stdout().write_all(&bytes_list.as_slice()).map_err(|e| Error::new(e))?;
        // stdout().flush().map_err(|e| Error::new(e))?;
        bytes_list = vec![];
    }
    Ok(())
}

// fn check_signal(status: WaitStatus) -> Result<()> {
// let pid = status.pid().unwrap();
fn fetch_signal(pid: Pid) -> Result<libc::siginfo_t> {
    println!("pid: {:?}", pid);
    let siginfo: libc::siginfo_t = ptrace::get_siginfo(pid).unwrap();
    println!("siginfo: {:?}, si_value: {:?}, si_addr: {:?}", siginfo, unsafe { siginfo.si_value() }, unsafe { siginfo.si_addr() });
    Ok(siginfo)
}

fn check_exited(status: WaitStatus) -> bool {
    match status {
        WaitStatus::Exited(pid, code) => true,
        _ => false,
    }
}

fn emulate(pid: Pid, regs: user_regs_struct, prev_orig_rax: u64) {
    let mut new_regs = regs.clone();
    // new_regs.rax = regs.rdx;
    new_regs.rax = 0;
    new_regs.orig_rax = 39;
    ptrace::setregs(pid, new_regs);

    let mut regs: user_regs_struct = ptrace::getregs(pid).unwrap();
    println!("Before Emulate!!!!! prev_orig_rax: {:?}, orig_rax: {:?}, rsi: {:?}, rdx: {:?}, rdi: {:?}, rax: {:?}", prev_orig_rax, regs.orig_rax, regs.rsi, regs.rdx, regs.rdi, regs.rax);
    sleep(Duration::from_secs(3));
    if regs.eflags & 1 << 8 != 0 {
        println!("sysemu_single!!!!!");
        ptrace::sysemu_single(pid);
    } else {
        ptrace::sysemu(pid);
    }
    println!("sysemu.");
}