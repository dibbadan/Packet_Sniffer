use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::sync::{Arc, Condvar, Mutex, RwLock};

/*pub struct MapData {
    pub map: Mutex<HashMap<key, (u32, String, String)>>,
}
*/

pub struct MapData {
    pub map: Mutex<HashMap<key, value>>,
}

#[derive(Clone, Hash, Debug, Eq, PartialEq)]
//pub struct key(IpAddr, IpAddr);
pub struct key(IpAddr, IpAddr, u16, u16);

pub struct value(u32, String, String, String);

impl value {
    pub fn new(bytes: u32, start_ts: String, end_ts: String, protocol: String) -> Self {
        value(bytes, start_ts, end_ts, protocol)
    }
    pub fn add_to_bytes(&mut self, bytes: u32) {
        self.0 += bytes;
    }

    pub fn set_start_ts(&mut self, start_ts: String) {
        self.1 = start_ts;
    }

    pub fn set_end_ts(&mut self, end_ts: String) {
        self.2 = end_ts;
    }
    pub fn set_protocol(&mut self, protocol: String) {
        self.3 = protocol;
    }
}

impl Display for value {
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

/*impl key {
    pub fn new(src: IpAddr, dst: IpAddr) -> Self {
        key(src, dst)
    }
}*/

impl key {
    pub fn new(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16) -> Self {
        key(src, dst, src_port, dst_port)
    }
}

impl Display for key {
    /*
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "\nSRC_ADDR = {}\nDST_ADDR = {}\nSRC_PORT = {}\nDST_PORT = {}\n", self.0.to_string(), self.1.to_string(), self.2.to_string(), self.3.to_string())
    }
     */
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{0: <20} | {1: <20} | {2: <15} | {3: <15}",
            self.0.to_string(),
            self.1.to_string(),
            self.2.to_string(),
            self.3.to_string()
        )
    }
}

impl Serialize for key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!(
            "SRC_ADDR = {} -- DST_ADDR = {}",
            self.0.to_string(),
            self.1.to_string()
        ))
    }
}

impl Serialize for value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!(
            "TOTAL_BYTES = {}, START_TS = {}, END_TS = {}, PROT = {} ",
            self.0.to_string(),
            self.1,
            self.2,
            self.3
        ))
    }
}

/*impl MapData {
    pub fn new() -> Self {
        MapData {
            map: Mutex::new(HashMap::<key, (u32, String, String)>::new()),
        }
    }
}*/

impl MapData {
    pub fn new() -> Self {
        MapData {
            map: Mutex::new(HashMap::<key, value>::new()),
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
