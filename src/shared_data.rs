use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

pub struct MapData {
    pub map: Mutex<HashMap<key, (u32, String, String)>>,
}

#[derive(Clone, Hash, Debug, Eq, PartialEq)]
pub struct key(IpAddr, IpAddr);

impl key {
    pub fn new(src: IpAddr, dst: IpAddr) -> Self {
        key(src, dst)
    }
}

impl Display for key {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.0.to_string(), self.1.to_string())
    }
}

impl Serialize for key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}-{}", self.0.to_string(), self.1.to_string()))
    }
}

impl MapData {
    pub fn new() -> Self {
        MapData {
            map: Mutex::new(HashMap::<key, (u32, String, String)>::new()),
        }
    }
}



pub struct SharedData {
    pub m: MapData,
}

impl SharedData {
    pub fn new() -> Arc<Self> {
        Arc::new(
            SharedData {
                m: MapData::new()
            }
        )
    }
}





