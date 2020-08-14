use nix::unistd::{Pid, getpid, sethostname, chroot, chdir, mkdir, pivot_root};

fn main() {
    println!("Hello, world!");
    println!("Hello, world PID: {:?}", getpid());
    loop {}
}
