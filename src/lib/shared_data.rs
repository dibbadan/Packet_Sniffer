use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::sync::{Arc, Condvar, Mutex};

pub struct MapData {
    pub map: Mutex<HashMap<Key, Value>>,
}

#[derive(Clone, Hash, Debug, Eq, PartialEq)]
pub struct Key(IpAddr, IpAddr, u16, u16);

pub struct Value(u32, String, String, String);

impl Value {
    pub fn new(bytes: u32, start_ts: String, end_ts: String, protocol: String) -> Self {
        Value(bytes, start_ts, end_ts, protocol)
    }
    pub fn add_to_bytes(&mut self, bytes: u32) {
        self.0 += bytes;
    }
    pub fn set_end_ts(&mut self, end_ts: String) {
        self.2 = end_ts;
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            " | {0: <15} | {1: <30} | {2: <30} | {3: <30} ",
            self.0.to_string(),
            self.1,
            self.2,
            self.3
        )
    }
}

impl Key {
    pub fn new(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16) -> Self {
        Key(src, dst, src_port, dst_port)
    }
}

impl Display for Key {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{0: <25} | {1: <25} | {2: <15} | {3: <15}",
            self.0.to_string(),
            self.1.to_string(),
            self.2.to_string(),
            self.3.to_string()
        )
    }
}


impl MapData {
    pub fn new() -> Self {
        MapData {
            map: Mutex::new(HashMap::<Key, Value>::new()),
        }
    }
}

pub struct SharedData {
    pub m: MapData,
}

impl SharedData {
    pub fn new() -> Arc<Self> {
        Arc::new(SharedData { m: MapData::new() })
    }
}

pub struct SharedPause {
    pub lock: Mutex<bool>,
    pub cv: Condvar,
}

impl SharedPause {
    pub fn new() -> Arc<Self> {
        Arc::new(SharedPause {
            lock: Mutex::new(false),
            cv: Condvar::new(),
        })
    }
}

pub struct SharedEnd {
    pub lock: Mutex<EndData>,
    pub cv: Condvar,
}

impl SharedEnd {
    pub fn new() -> Arc<Self> {
        Arc::new(SharedEnd {
            lock: Mutex::new(EndData::new()),
            cv: Condvar::new(),
        })
    }
}

pub struct EndData {
    pub buf: String,
    pub present: bool,
    pub result: std::io::Result<usize>,
    pub terminated: usize,
}

impl EndData {
    pub fn new() -> EndData {
        EndData {
            buf: String::new(),
            present: false,
            result: Ok(0),
            terminated: 0,
        }
    }
}
