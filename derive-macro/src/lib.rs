use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use proc_macro2::{Ident, Span};
use quote::quote;
use syn::{self, DataStruct, DeriveInput, Field};

// This is a convenience macro which implements accessors of the
// `trait ProverGetSet`
#[proc_macro_derive(ProverGetSetM)]
pub fn prover_get_set_m_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();
    // Build the impl
    let gen = produce(&ast, "Prover");
    // Return the generated impl
    gen.into()
}

// This is a convenience macro which implements accessors of
// `trait VerifierGetSet`
#[proc_macro_derive(VerifierGetSetM)]
pub fn verifier_get_set_m_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();
    // Build the impl
    let gen = produce(&ast, "Verifier");
    // Return the generated impl
    gen.into()
}

fn produce(ast: &DeriveInput, role: &str) -> TokenStream2 {
    let name = &ast.ident;
    let trait_name = Ident::new(&format!("{}{}", role, "GetSet"), Span::call_site());

    // Is it a struct?
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
