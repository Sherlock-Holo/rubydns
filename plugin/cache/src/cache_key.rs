use std::fmt;
use std::fmt::{Debug, Formatter};
use std::ops::{Deref, DerefMut};

use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use trust_dns_proto::op::Query;
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheKey {
    pub query: Vec<QueryDef>,
}

pub struct QueryDef(Query);

impl Debug for QueryDef {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl From<Query> for QueryDef {
    fn from(value: Query) -> Self {
        Self(value)
    }
}

impl Deref for QueryDef {
    type Target = Query;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for QueryDef {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Serialize for QueryDef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::Error;

        let data = self.0.to_bytes().map_err(Error::custom)?;

        serializer.serialize_bytes(&data)
    }
}

impl<'de> Deserialize<'de> for QueryDef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = deserializer.deserialize_bytes(BytesVisitor)?;

        Query::from_bytes(data).map_err(Error::custom).map(QueryDef)
    }
}

struct BytesVisitor;

impl<'a> Visitor<'a> for BytesVisitor {
    type Value = &'a [u8];

    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str("a borrowed byte array")
    }

    fn visit_borrowed_str<E>(self, v: &'a str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(v.as_bytes())
    }

    fn visit_borrowed_bytes<E>(self, v: &'a [u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(v)
    }
}
