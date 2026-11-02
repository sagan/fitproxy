pub mod direct;
pub mod http;
pub mod socks5;

pub use direct::handle_direct;
pub use http::handle_http_proxy;
pub use socks5::handle_socks5_proxy;
