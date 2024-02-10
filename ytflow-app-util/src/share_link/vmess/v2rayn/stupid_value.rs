use std::borrow::Cow;
use std::fmt::Display;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct StupidValue<T>(pub T);

impl<T> Serialize for StupidValue<T>
where
    T: ToString,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.to_string().serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for StupidValue<T>
where
    T: FromStr + Deserialize<'de>,
    T::Err: Display,
{
    fn deserialize<D>(deserializer: D) -> Result<StupidValue<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StrOrValue<'a, T> {
            Str(Cow<'a, str>),
            Value(T),
        }

        let str_or_val = StrOrValue::<T>::deserialize(deserializer)?;
        Ok(StupidValue(match str_or_val {
            StrOrValue::Value(val) => val,
            StrOrValue::Str(s) => s.parse().map_err(serde::de::Error::custom)?,
        }))
    }
}

impl<T> From<T> for StupidValue<T> {
    fn from(val: T) -> Self {
        StupidValue(val)
    }
}
