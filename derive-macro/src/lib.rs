use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use proc_macro2::{Ident, Span};
use quote::quote;
use syn::{self, DataStruct, DeriveInput, Field};

// An attribute macro which creates a trait definition for accessors for each
// field of the struct
#[proc_macro_attribute]
pub fn define_accessors_trait(trait_name: TokenStream, input: TokenStream) -> TokenStream {
    let ast = syn::parse(input.clone()).unwrap();
    // Build the definition
    let gen = produce_trait_definition(&ast, &trait_name.to_string());
    // An attribute macro overwrites the original input with its output. But we
    // want to preserve the original input and append to it the generated stream.

    // TokenStream can't extend, so we convert to TokenStream2 and extend
    let mut out = TokenStream2::from(input);
    out.extend(gen);
    out.into()
}

// A derive macro which implements accessors defined in `trait ProverDataGetSet`
#[proc_macro_derive(ProverDataGetSet)]
pub fn prover_data_get_set_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();
    // Build the impl
    let gen = produce_trait_implementation(&ast, "ProverData");
    // Return the generated impl
    gen.into()
}

// A derive macro which implements accessors defined in `trait VerifierDataGetSet`
#[proc_macro_derive(VerifierDataGetSet)]
pub fn verifier_get_set_m_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();
    // Build the impl
    let gen = produce_trait_implementation(&ast, "VerifierData");
    // Return the generated impl
    gen.into()
}

fn produce_trait_implementation(ast: &DeriveInput, role: &str) -> TokenStream2 {
    let name = &ast.ident;
    let trait_name = Ident::new(&format!("{}{}", role, "GetSet"), Span::call_site());

    if let syn::Data::Struct(DataStruct { ref fields, .. }) = ast.data {
        let generated = fields.iter().map(|f| implement(f));

        quote! {
            impl #trait_name for #name {
                #(#generated)*
            }
        }
    } else {
        // Nope. This is an Enum. We are not supporting these!
        panic!("can only handle structs, not enums!");
    }
}

fn produce_trait_definition(ast: &DeriveInput, trait_name: &str) -> TokenStream2 {
    let trait_name = Ident::new(&format!("{}", trait_name), Span::call_site());

    // Is it a struct?
    if let syn::Data::Struct(DataStruct { ref fields, .. }) = ast.data {
        let generated = fields.iter().map(|f| define(f));

        quote! {
            pub trait #trait_name {
                #(#generated)*
            }
        }
    } else {
        // Nope. This is an Enum. We are not supporting these!
        panic!("can only handle structs, not enums!");
    }
}

// Implements accessors for a field of a struct
fn implement(field: &Field) -> TokenStream2 {
    let field_name = field.clone().ident.unwrap();
    let ty = field.ty.clone();
    let get_name = field_name.clone();
    let set_name = Ident::new(&format!("{}{}", "set_", field_name), Span::call_site());
    return quote! {
        fn #get_name(&self) -> &#ty {
            &self.#field_name
        }
        fn #set_name(&mut self, new: #ty) {
            self.#field_name = new;
        }
    };
}

// Defines trait's accessors for a field of a struct
fn define(field: &Field) -> TokenStream2 {
    let field_name = field.clone().ident.unwrap();
    let ty = field.ty.clone();
    let get_name = field_name.clone();
    let set_name = Ident::new(&format!("{}{}", "set_", field_name), Span::call_site());
    return quote! {
        fn #get_name(&self) -> &#ty;
        fn #set_name(&mut self, new: #ty);
    };
}
