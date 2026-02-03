#[cfg(unix)]
mod posix;
#[cfg(unix)]
pub use posix::add_routes;
pub use posix::get_gateway_for;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::add_routes;
