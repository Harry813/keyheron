//! Relay only the two connected sockets inherited from a trusted Warden.
use anyhow::{ensure, Context, Result};
use std::io;
use std::mem::size_of_val;
use std::net::TcpStream as StdTcpStream;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::time::Duration;
use tokio::io::{copy_bidirectional_with_sizes, AsyncReadExt};
use tokio::net::{TcpStream, UnixStream};

fn connected_stream(fd: RawFd, expected_family: libc::c_int) -> Result<OwnedFd> {
    // Duplicate first: the supplied number may be closed or refer to something other than a socket.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let mut kind: libc::c_int = 0;
    let mut length = size_of_val(&kind) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            duplicate,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    ensure!(
        result == 0 && kind == libc::SOCK_STREAM,
        "需要已连接的流式套接字"
    );
    let mut peer = std::mem::MaybeUninit::<libc::sockaddr_storage>::uninit();
    let mut length = size_of_val(&peer) as libc::socklen_t;
    let result = unsafe { libc::getpeername(duplicate, peer.as_mut_ptr().cast(), &mut length) };
    ensure!(result == 0, "需要已连接的套接字");
    let family = unsafe { (*peer.as_ptr()).ss_family };
    ensure!(
        libc::c_int::from(family) == expected_family,
        "套接字类型不匹配"
    );
    Ok(owned)
}

fn unix_stream(fd: RawFd) -> Result<UnixStream> {
    let socket = StdUnixStream::from(connected_stream(fd, libc::AF_UNIX)?);
    socket.set_nonblocking(true)?;
    Ok(UnixStream::from_std(socket)?)
}

pub async fn run(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 3,
        "db-relay 需要两个套接字和会话剩余时限"
    );
    let agent_fd: RawFd = args[0].parse().context("Agent 套接字无效")?;
    let broker_fd: RawFd = args[1].parse().context("数据库套接字无效")?;
    ensure!(
        agent_fd > 2 && broker_fd > 2 && agent_fd != broker_fd,
        "套接字不可复用"
    );
    let ttl_ms: u64 = args[2].parse().context("会话时限无效")?;
    ensure!((1..=900_000).contains(&ttl_ms), "会话时限无效");

    let mut parent = unix_stream(0)?;
    let mut agent = unix_stream(agent_fd)?;
    let broker = StdTcpStream::from(connected_stream(broker_fd, libc::AF_INET)?);
    ensure!(
        broker.peer_addr()?.ip().is_loopback() && broker.local_addr()?.ip().is_loopback(),
        "只接受本机数据库代理已建立的回环连接"
    );
    broker.set_nonblocking(true)?;
    let mut broker = TcpStream::from_std(broker)?;
    let mut stop = [0; 1];
    tokio::select! {
        biased;
        _ = parent.read(&mut stop) => {},
        _ = tokio::time::sleep(Duration::from_millis(ttl_ms)) => {},
        result = copy_bidirectional_with_sizes(&mut agent, &mut broker, 65536, 65536) => { result?; },
    }
    Ok(())
}
