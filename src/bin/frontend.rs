#![cfg_attr(all(target_arch = "wasm32", feature = "csr"), no_main)]

#[cfg(all(target_arch = "wasm32", feature = "csr"))]
#[wasm_bindgen::prelude::wasm_bindgen(start)]
/// Mounts the frontend application in a browser.
pub fn start() {
    papra_vector_search::mount();
}

#[cfg(not(all(target_arch = "wasm32", feature = "csr")))]
fn main() {}
