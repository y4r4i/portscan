use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use indicatif::{ParallelProgressIterator, ProgressStyle};
use rayon::prelude::*;

use clap::Parser;

/// Port Scanning Tool
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Search target ip address
    ipaddr: String,
    /// Start number of port search range
    #[arg(short, long, default_value_t = 1)]
    start: u32,
    /// End number of the port search range
    #[arg(short, long, default_value_t = 65535)]
    end: u32,
    /// Timeout seconds
    #[arg(short, long, default_value_t = 0.04)]
    timeout: f32
}

fn scan(ipaddr: String, port: u32, timeout: f32) -> (bool, bool) {
    let addr: SocketAddr = format!("{}:{}", ipaddr, port).parse().unwrap();
    (
        match TcpStream::connect_timeout(&addr, Duration::from_secs_f32(timeout)) {
            Ok(_) => true,
            Err(_) => false
        },
        match UdpSocket::bind(addr) {
            Ok(_) => true,
            Err(_) => false
        }
    )
}

fn main() {
    let args = Args::parse();
    let ports: Vec<_> = (args.clone().start..=args.clone().end).collect();
    let now = Instant::now();
    let style: ProgressStyle = ProgressStyle::with_template("Scanning: [{bar:40.cyan/blue}] {pos:>7}/{len:7} [{elapsed_precise}]")
        .unwrap()
        .progress_chars("#>-");
    let ports: HashMap<&u32, (bool, bool)> = ports
        .par_iter()
        .progress_with_style(style)
        .map(|port| {
            (port, scan(args.clone().ipaddr, port.clone(), args.clone().timeout))
        })
        .collect();
    let mut tcp = HashMap::new();
    tcp.clone_from(&ports);
    let tcp: HashMap<_, _> = tcp.par_iter().filter(|(&_k, &v)| v.0).collect();
    let mut udp = HashMap::new();
    udp.clone_from(&ports);
    let udp: HashMap<_, _> = udp.par_iter().filter(|(&_k, &v)| v.1).collect();
    println!("TCP: {:?}", tcp.keys());
    println!("UDP: {:?}", udp.keys());
    println!("{:?}", now.elapsed());
}