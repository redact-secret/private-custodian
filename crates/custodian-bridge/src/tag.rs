//! A closed schema tag: serializes to one fixed string and rejects every other
//! value, so a document of another type or major never deserializes as this
//! one. Same behavior as the contracts crate's tags, kept local because that
//! macro is private to its crate.

macro_rules! schema_tag {
    ($(#[$m:meta])* $name:ident, $value:literal) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
        pub struct $name;

        impl $name {
            pub const VALUE: &'static str = $value;
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, s: S) -> ::core::result::Result<S::Ok, S::Error> {
                s.serialize_str($value)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> ::core::result::Result<Self, D::Error> {
                let s = <String as ::serde::Deserialize>::deserialize(d)?;
                if s == $value {
                    Ok(Self)
                } else {
                    Err(<D::Error as ::serde::de::Error>::custom("schema_tag"))
                }
            }
        }

        impl ::schemars::JsonSchema for $name {
            fn schema_name() -> ::std::borrow::Cow<'static, str> {
                ::std::borrow::Cow::Borrowed(stringify!($name))
            }
            fn inline_schema() -> bool {
                true
            }
            fn json_schema(_: &mut ::schemars::SchemaGenerator) -> ::schemars::Schema {
                ::schemars::json_schema!({"const": $value})
            }
        }
    };
}
pub(crate) use schema_tag;
