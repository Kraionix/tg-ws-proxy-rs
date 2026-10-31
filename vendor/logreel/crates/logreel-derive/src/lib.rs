//! Derive macro for logreel events.
//!
//! The macro emits token-only code: it never depends on the runtime crates at
//! compile time. A struct derive generates kind, encode and decode through
//! the consumer's codec (prost in v0.1). An enum derive generates the domain
//! dispatch and the domain constants.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::spanned::Spanned;
use syn::{
    Attribute, Data, DataEnum, DataStruct, DeriveInput, Fields, LitInt, LitStr, Path,
    parse_macro_input,
};

/// Derive the logreel Event contract.
///
/// Struct attributes:
/// - kind = N (required)
/// - codec = "prost" (default)
/// - codec_id = N, schema_hash = "32 hex chars", kind_count = N, base = N
/// - crate = "logreel" (path to the runtime crate; default logreel_core)
///
/// Enum attributes take the domain constants once; each variant carries
/// #[event(kind = N)] and exactly one field that itself implements Event.
#[proc_macro_derive(Event, attributes(event))]
pub fn derive_event(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

#[derive(Default)]
struct Attrs {
    kind: Option<u16>,
    codec: Option<String>,
    codec_id: Option<u16>,
    schema_hash: Option<[u8; 16]>,
    kind_count: Option<u16>,
    base: Option<u16>,
    krate: Option<Path>,
}

fn parse_attrs(attrs: &[Attribute]) -> syn::Result<Attrs> {
    let mut out = Attrs::default();
    for attr in attrs {
        if !attr.path().is_ident("event") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("kind") {
                out.kind = Some(meta.value()?.parse::<LitInt>()?.base10_parse()?);
            } else if meta.path.is_ident("codec") {
                out.codec = Some(meta.value()?.parse::<LitStr>()?.value());
            } else if meta.path.is_ident("codec_id") {
                out.codec_id = Some(meta.value()?.parse::<LitInt>()?.base10_parse()?);
            } else if meta.path.is_ident("schema_hash") {
                let literal = meta.value()?.parse::<LitStr>()?;
                out.schema_hash = Some(parse_hash(&literal)?);
            } else if meta.path.is_ident("kind_count") {
                out.kind_count = Some(meta.value()?.parse::<LitInt>()?.base10_parse()?);
            } else if meta.path.is_ident("base") {
                out.base = Some(meta.value()?.parse::<LitInt>()?.base10_parse()?);
            } else if meta.path.is_ident("crate") {
                let literal = meta.value()?.parse::<LitStr>()?;
                out.krate = Some(syn::parse_str(&literal.value())?);
            } else {
                return Err(meta.error(
                    "unknown event attribute; expected kind, codec, codec_id, schema_hash, kind_count, base or crate",
                ));
            }
            Ok(())
        })?;
    }
    Ok(out)
}

fn parse_hash(literal: &LitStr) -> syn::Result<[u8; 16]> {
    let value = literal.value();
    if value.len() != 32 {
        return Err(syn::Error::new(
            literal.span(),
            "schema_hash must contain exactly 32 hexadecimal characters",
        ));
    }
    let mut bytes = [0u8; 16];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let pair = &value[index * 2..index * 2 + 2];
        *slot = u8::from_str_radix(pair, 16)
            .map_err(|_| syn::Error::new(literal.span(), "schema_hash is not hexadecimal"))?;
    }
    Ok(bytes)
}

fn hash_tokens(hash: [u8; 16]) -> TokenStream2 {
    let bytes = hash.iter().map(|byte| quote! { #byte });
    quote! { [ #( #bytes ),* ] }
}

fn expand(input: DeriveInput) -> syn::Result<TokenStream2> {
    let attrs = parse_attrs(&input.attrs)?;
    let krate: Path = attrs
        .krate
        .clone()
        .unwrap_or_else(|| syn::parse_quote!(::logreel_core));
    match &input.data {
        Data::Struct(data) => expand_struct(&input, data, &attrs, &krate),
        Data::Enum(data) => expand_enum(&input, data, &attrs, &krate),
        Data::Union(_) => Err(syn::Error::new(
            input.span(),
            "Event cannot be derived for a union",
        )),
    }
}

fn expand_struct(
    input: &DeriveInput,
    _data: &DataStruct,
    attrs: &Attrs,
    krate: &Path,
) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let kind = attrs.kind.ok_or_else(|| {
        syn::Error::new(
            input.span(),
            "missing #[event(kind = N)] on the event struct",
        )
    })?;
    let codec = attrs.codec.as_deref().unwrap_or("prost");
    if codec != "prost" {
        return Err(syn::Error::new(
            input.span(),
            format!("unsupported codec {codec}; v0.1 supports prost"),
        ));
    }
    let codec_id = attrs.codec_id.unwrap_or(0);
    let kinds = attrs.kind_count.unwrap_or(0);
    let base = attrs.base.unwrap_or(0);
    let hash = hash_tokens(attrs.schema_hash.unwrap_or([0u8; 16]));
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #krate::Event for #name #type_generics #where_clause {
            const CODEC_ID: u16 = #codec_id;
            const SCHEMA_HASH: [u8; 16] = #hash;
            const KINDS: u16 = #kinds;
            const BASE: u16 = #base;

            fn kind(&self) -> u16 {
                #kind
            }

            fn encode(&self, out: &mut Vec<u8>) {
                ::prost::Message::encode(self, out)
                    .expect("prost encoding into Vec<u8> cannot fail");
            }

            fn decode(kind: u16, bytes: &[u8]) -> Result<Self, #krate::DecodeError> {
                if kind != #kind {
                    return Err(#krate::DecodeError::new(
                        kind,
                        "kind does not match the event type",
                    ));
                }
                ::prost::Message::decode(bytes)
                    .map_err(|error| #krate::DecodeError::new(kind, error.to_string()))
            }
        }
    })
}

fn expand_enum(
    input: &DeriveInput,
    data: &DataEnum,
    attrs: &Attrs,
    krate: &Path,
) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let codec_id = attrs.codec_id.unwrap_or(0);
    let base = attrs.base.unwrap_or(0);
    let hash = hash_tokens(attrs.schema_hash.unwrap_or([0u8; 16]));
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    let mut seen = BTreeSet::new();
    let mut max_kind = 0u16;
    let mut kind_arms = Vec::new();
    let mut encode_arms = Vec::new();
    let mut decode_arms = Vec::new();

    for variant in &data.variants {
        let variant_attrs = parse_attrs(&variant.attrs)?;
        let kind = variant_attrs.kind.ok_or_else(|| {
            syn::Error::new(
                variant.span(),
                "missing #[event(kind = N)] on the enum variant",
            )
        })?;
        if !seen.insert(kind) {
            return Err(syn::Error::new(
                variant.span(),
                format!("duplicate kind {kind} in the event enum"),
            ));
        }
        max_kind = max_kind.max(kind);
        let Fields::Unnamed(fields) = &variant.fields else {
            return Err(syn::Error::new(
                variant.span(),
                "an event variant must be a tuple variant with one field",
            ));
        };
        if fields.unnamed.len() != 1 {
            return Err(syn::Error::new(
                variant.span(),
                "an event variant must carry exactly one field",
            ));
        }
        let inner = &fields.unnamed[0].ty;
        let ident = &variant.ident;
        kind_arms.push(quote! { Self::#ident(_) => #kind });
        encode_arms.push(quote! {
            Self::#ident(inner) => #krate::Event::encode(inner, out),
        });
        decode_arms.push(quote! {
            #kind => Ok(Self::#ident(<#inner as #krate::Event>::decode(kind, bytes)?)),
        });
    }

    let kinds = attrs.kind_count.unwrap_or(max_kind.saturating_add(1));

    Ok(quote! {
        impl #impl_generics #krate::Event for #name #type_generics #where_clause {
            const CODEC_ID: u16 = #codec_id;
            const SCHEMA_HASH: [u8; 16] = #hash;
            const KINDS: u16 = #kinds;
            const BASE: u16 = #base;

            fn kind(&self) -> u16 {
                match self {
                    #( #kind_arms ),*
                }
            }

            fn encode(&self, out: &mut Vec<u8>) {
                match self {
                    #( #encode_arms )*
                }
            }

            fn decode(kind: u16, bytes: &[u8]) -> Result<Self, #krate::DecodeError> {
                match kind {
                    #( #decode_arms )*
                    _ => Err(#krate::DecodeError::new(kind, "unknown kind")),
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{expand, parse_hash};
    use quote::quote;
    use syn::parse_quote;

    #[test]
    fn duplicate_kinds_are_rejected() {
        let input = parse_quote! {
            #[event(codec_id = 1)]
            enum Domain {
                #[event(kind = 0)]
                A(First),
                #[event(kind = 0)]
                B(Second),
            }
        };
        let error = expand(input).expect_err("duplicate kind must fail");
        assert!(error.to_string().contains("duplicate kind 0"));
    }

    #[test]
    fn missing_kind_is_rejected() {
        let input = parse_quote! {
            struct Event {
                value: u64,
            }
        };
        let error = expand(input).expect_err("missing kind must fail");
        assert!(error.to_string().contains("missing"));
    }

    #[test]
    fn enum_constants_come_from_attributes() {
        let input = parse_quote! {
            #[event(codec_id = 3, kind_count = 9, schema_hash = "00112233445566778899aabbccddeeff", crate = "logreel")]
            enum Domain {
                #[event(kind = 2)]
                A(First),
            }
        };
        let tokens = expand(input).expect("expand");
        let text = tokens.to_string();
        assert!(text.contains("const CODEC_ID : u16 = 3u16"));
        assert!(text.contains("const KINDS : u16 = 9u16"));
        assert!(text.contains("logreel :: Event"));
        let _ = quote! {};
    }

    #[test]
    fn hash_parser_checks_length_and_digits() {
        let short: syn::LitStr = parse_quote!("0011");
        assert!(parse_hash(&short).is_err());
        let bad: syn::LitStr = parse_quote!("zz112233445566778899aabbccddeeff");
        assert!(parse_hash(&bad).is_err());
    }
}
