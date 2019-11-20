use std::net::SocketAddr;
use std::time::Duration;

use log::{info, error};
use env_logger::Builder as EnvBuilder;
use hashbrown::HashMap;
use tokio::codec::{FramedRead, LinesCodec, LinesCodecError};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio::runtime::{Builder, TaskExecutor};

use lazy_static::lazy_static;

lazy_static! {
    static ref WHOIS_LUT: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("ad", "whois.ripe.net");
        m.insert("ae", "whois.aeda.net.ae");
        m.insert("aero", "whois.aero");
        m.insert("af", "whois.nic.af");
        m.insert("ca", "whois.cira.ca");
        m.insert("ch", "whois.nic.ch");
        m.insert("co", "whois.nic.co");
        m.insert("com", "whois.verisign-grs.com");
        m.insert("dev", "whois.nic.google");
        m.insert("in", "whois.registry.in");
        m.insert("io", "whois.nic.io");
        m.insert("net", "whois.verisign-grs.com");
        m.insert("org", "whois.publicregistry.net");
        m
    };
}
#[derive(Debug)]
pub enum RWhoisError {
    CodecError(LinesCodecError),
    InvalidDomainError
}

async fn rwhois_process(mut stream: TcpStream, addr: SocketAddr) -> Result<(), RWhoisError> {
    let (client_read, mut client_write) = stream.split();
    let mut codec = FramedRead::new(client_read, LinesCodec::new());

    loop {
        match codec.next().await {
            Some(line) => match line {
                Ok(ref l) => {
                    //println!("{}: {}", addr, l);
                    let splits: Vec<&str> = l.split_whitespace().collect();
                    if splits.len() == 1 {
                        //let hostname = splits[0].clone();
                        let pairs: Vec<&str> = splits[0].split(".").collect();
                        if pairs.len() > 1 {
                            let total_pairs = pairs.len();
                            if let Some(whois_hostname) = WHOIS_LUT.get(pairs[total_pairs - 1]) {
                                info!(
                                    "Would use whois server: {} for {}",
                                    whois_hostname, splits[0]
                                );
                                let whois_addr = format!("{}:43", whois_hostname);
                                if let Ok(mut whois_stream) = TcpStream::connect(&whois_addr).await
                                {
                                    let request = format!("{}\r\n", splits[0]);
                                    let (mut whois_read, mut whois_write) = whois_stream.split();
                                    if let Ok(_) = whois_write.write_all(request.as_bytes()).await {
                                        if let Err(e) = whois_read.copy(&mut client_write).await {
                                            error!(
                                                "unable to write back response to {}: {:?}",
                                                addr, e
                                            );
                                        }
                                    }
                                } else {
                                    error!(
                                        "unable to connect to whois server: {}",
                                        &whois_hostname
                                    );
                                }
                            } else {
                                let _ = client_write.write_all("Invalid domain name".as_bytes()).await;
                                return Err(RWhoisError::InvalidDomainError);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "an error occurred while processing messages for {}; error = {:?}",
                        addr, e
                    );
                }
            },
            None => {
                info!("{}: close", addr);
                return Ok(());
            }
        }
    }
}

async fn rwhois_serve(exec: TaskExecutor, addr: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut listener = TcpListener::bind(&addr).await?;
    info!("rwhois server running on {}", &addr);

    loop {
        let (stream, addr) = listener.accept().await?;

        exec.spawn(async move {
            if let Err(e) = rwhois_process(stream, addr).await {
                error!("rwhois_process error; error = {:?}", e);
            }
        });
    }
}

fn main() {
    //let mut env_log_builder = EnvBuilder::new();
    //env_log_builder.parse_filters("*");
    //env_log_builder.init();
    env_logger::init();

    let rt = Builder::new()
        .core_threads(num_cpus::get_physical())
        .blocking_threads(num_cpus::get_physical())
        .keep_alive(Some(Duration::from_secs(10)))
        .name_prefix("rwhois-")
        .build()
        .unwrap();

    let addr = "127.0.0.1:9000".to_string();
    match rt.block_on(rwhois_serve(rt.executor(), addr)) {
        Ok(_) => {}
        Err(e) => {
            //eprintln!("rwhois_serve; error = {:?}", e);
            error!("rwhois serve; error = {:?}", e);
        }
    }
}
