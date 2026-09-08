use leptos::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct SearchResult {
    pub organization_id: String,
    pub papra_document_id: String,
    pub title: String,
    pub source_url: Option<String>,
    pub score: f32,
}

#[derive(Clone, Debug, Deserialize)]
#[cfg(target_arch = "wasm32")]
struct SearchResponse {
    results: Vec<SearchResult>,
}

#[derive(Debug, Deserialize)]
#[cfg(target_arch = "wasm32")]
struct LoginResponse {
    authorization_url: String,
}

#[derive(Debug, Deserialize)]
#[cfg(target_arch = "wasm32")]
struct HealthResponse {
    auth_enabled: bool,
}

#[component]
pub fn App() -> impl IntoView {
    let token = RwSignal::new(None::<String>);
    let auth_enabled = RwSignal::new(true);
    let query = RwSignal::new(String::new());
    let results = RwSignal::new(Vec::<SearchResult>::new());
    let loading = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let has_searched = RwSignal::new(false);

    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast;
        use wasm_bindgen::closure::Closure;

        let token_for_message = token;
        let listener =
            Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |event: web_sys::MessageEvent| {
                let app_origin = web_sys::window()
                    .and_then(|window| window.location().origin().ok())
                    .unwrap_or_default();
                let is_local_backend = matches!(
                    event.origin().as_str(),
                    "http://127.0.0.1:3000" | "http://localhost:3000"
                );
                if event.origin() != app_origin && !is_local_backend {
                    return;
                }
                let data = event.data();
                let id_token = data
                    .dyn_into::<js_sys::Object>()
                    .ok()
                    .and_then(|object| js_sys::Reflect::get(&object, &"id_token".into()).ok())
                    .and_then(|value| value.as_string());
                if let Some(id_token) = id_token {
                    token_for_message.set(Some(id_token.clone()));
                    let _ = web_sys::window()
                        .and_then(|window| window.local_storage().ok().flatten())
                        .map(|storage| storage.set_item("papra_id_token", &id_token));
                }
            });
        web_sys::window()
            .expect("browser window")
            .add_event_listener_with_callback("message", listener.as_ref().unchecked_ref())
            .expect("register OIDC message listener");
        listener.forget();

        if let Some(saved) = web_sys::window()
            .and_then(|window| window.local_storage().ok().flatten())
            .and_then(|storage| storage.get_item("papra_id_token").ok().flatten())
        {
            token.set(Some(saved));
        }

        let auth_enabled = auth_enabled;
        wasm_bindgen_futures::spawn_local(async move {
            let window = web_sys::window().expect("browser window");
            let Ok(response) =
                wasm_bindgen_futures::JsFuture::from(window.fetch_with_str("/health")).await
            else {
                return;
            };
            let response = web_sys::Response::from(response);
            let Ok(body) = wasm_bindgen_futures::JsFuture::from(
                response.json().expect("read health response"),
            )
            .await
            else {
                return;
            };
            if let Ok(health) = serde_wasm_bindgen::from_value::<HealthResponse>(body) {
                auth_enabled.set(health.auth_enabled);
            }
        });
    }

    let login = move |_| {
        #[cfg(target_arch = "wasm32")]
        {
            let popup = web_sys::window().and_then(|window| {
                window
                    .open_with_url_and_target("about:blank", "papra-login")
                    .ok()
                    .flatten()
            });
            wasm_bindgen_futures::spawn_local(async move {
                let window = web_sys::window().expect("browser window");
                let response = match wasm_bindgen_futures::JsFuture::from(
                    window.fetch_with_str("/oidc/login?format=json"),
                )
                .await
                {
                    Ok(value) => web_sys::Response::from(value),
                    Err(_) => return,
                };
                let body = match wasm_bindgen_futures::JsFuture::from(
                    response.json().expect("read login response"),
                )
                .await
                {
                    Ok(body) => body,
                    Err(_) => return,
                };
                if let Ok(login) = serde_wasm_bindgen::from_value::<LoginResponse>(body) {
                    if let Some(popup) = popup {
                        let _ = popup.location().set_href(&login.authorization_url);
                    }
                }
            });
        }
    };

    let logout = move |_| {
        token.set(None);
        results.set(Vec::new());
        has_searched.set(false);
        #[cfg(target_arch = "wasm32")]
        if let Some(storage) =
            web_sys::window().and_then(|window| window.local_storage().ok().flatten())
        {
            let _ = storage.remove_item("papra_id_token");
        }
    };

    let submit = move |event: leptos::ev::SubmitEvent| {
        event.prevent_default();
        let trimmed = query.get().trim().to_owned();
        has_searched.set(true);
        error.set(None);
        results.set(Vec::new());
        if trimmed.chars().count() == 0 || trimmed.chars().count() > 1_000 {
            error.set(Some(
                "Searches must contain 1 to 1,000 characters.".to_owned(),
            ));
            return;
        }
        let id_token = token.get();
        if auth_enabled.get() && id_token.is_none() {
            error.set(Some("Sign in with Google before searching.".to_owned()));
            return;
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = id_token;
        loading.set(true);

        #[cfg(target_arch = "wasm32")]
        {
            let encoded = js_sys::encode_uri_component(&trimmed);
            let token = token;
            wasm_bindgen_futures::spawn_local(async move {
                let request = web_sys::Request::new_with_str(&format!("/api/search?q={encoded}"))
                    .expect("create search request");
                if let Some(id_token) = id_token {
                    let authorization = ["Bearer ", id_token.as_str()].concat();
                    request
                        .headers()
                        .set("Authorization", &authorization)
                        .expect("set authorization header");
                }
                let window = web_sys::window().expect("browser window");
                let response =
                    match wasm_bindgen_futures::JsFuture::from(window.fetch_with_request(&request))
                        .await
                    {
                        Ok(value) => web_sys::Response::from(value),
                        Err(_) => {
                            loading.set(false);
                            error.set(Some("The search service could not be reached.".to_owned()));
                            return;
                        }
                    };
                if response.status() == 401 {
                    token.set(None);
                    let _ = window.open_with_url_and_target("/oidc/login", "papra-login");
                    loading.set(false);
                    error.set(Some(
                        "Your session expired. Please sign in again.".to_owned(),
                    ));
                    return;
                }
                if !response.ok() {
                    loading.set(false);
                    error.set(Some(
                        "The search service returned an error. Try again.".to_owned(),
                    ));
                    return;
                }
                let body = match wasm_bindgen_futures::JsFuture::from(
                    response.json().expect("read search response"),
                )
                .await
                {
                    Ok(body) => body,
                    Err(_) => {
                        loading.set(false);
                        error.set(Some("The search response was invalid.".to_owned()));
                        return;
                    }
                };
                match serde_wasm_bindgen::from_value::<SearchResponse>(body) {
                    Ok(response) => results.set(response.results),
                    Err(_) => error.set(Some("The search response was invalid.".to_owned())),
                }
                loading.set(false);
            });
        }
    };

    view! {
        <style>{STYLE}</style>
        <header class="topbar">
            <a class="brand" href="/" aria-label="Papra Search home">
                <span class="brand-mark" aria-hidden="true">"⌕"</span>
                <span>"Papra Search"</span>
            </a>
            <Show
                when=move || auth_enabled.get() && token.get().is_some()
                fallback=move || view! { <button class="button button-quiet" on:click=login>"Sign in with Google"</button> }
            >
                <button class="button button-quiet" on:click=logout>"Sign out"</button>
            </Show>
        </header>
        <main class="shell">
            <section class="hero">
                <p class="eyebrow">"Your documents, meaningfully connected."</p>
                <h1>"Find the thread in your knowledge."</h1>
                <p class="lede">"Search your Papra organization with natural language and jump straight to the source document."</p>
            </section>
            <Show
                when=move || !auth_enabled.get() || token.get().is_some()
                fallback=move || view! {
                    <section class="panel sign-in-panel">
                        <div class="panel-icon" aria-hidden="true">"✦"</div>
                        <h2>"Sign in to search your documents"</h2>
                        <p>"Use your authorized Google account to access your organization’s private index."</p>
                        <button class="button button-primary" on:click=login>"Continue with Google"</button>
                    </section>
                }
            >
                <form class="search-form" on:submit=submit>
                    <label for="search-query">"What are you looking for?"</label>
                    <div class="search-row">
                        <input id="search-query" type="search" placeholder="Try “project launch notes”" autocomplete="off" prop:value=query on:input=move |event| query.set(event_target_value(&event)) aria-describedby="search-help"/>
                        <button class="button button-primary" type="submit" disabled=move || loading.get()>
                            {move || if loading.get() { "Searching…" } else { "Search" }}
                        </button>
                    </div>
                    <p id="search-help" class="field-help">"Search up to 1,000 characters. Press Enter to search."</p>
                </form>
                <Show when=move || loading.get()>
                    <div class="status" role="status"><span class="spinner"></span>"Searching your documents…"</div>
                </Show>
                <Show when=move || error.get().is_some()>
                    <div class="alert" role="alert">{move || error.get().unwrap_or_default()}</div>
                </Show>
                <Show when=move || !loading.get() && error.get().is_none() && has_searched.get() && results.get().is_empty()>
                    <div class="panel empty"><h2>"No matching documents"</h2><p>"Try a broader phrase or a different description."</p></div>
                </Show>
                <Show when=move || !results.get().is_empty()>
                    <section class="results" aria-live="polite">
                        <div class="results-heading"><h2>"Search results"</h2><span>{move || format!("{} found", results.get().len())}</span></div>
                        <For each=move || results.get() key=|result| result.papra_document_id.clone() let:result>
                            <article class="result-card">
                                <div class="result-thumb" aria-hidden="true">
                                    {result.title.chars().next().map(|c| c.to_string()).unwrap_or_else(|| "DOC".to_owned())}
                                </div>
                                <div class="result-copy">
                                    <p class="result-org">{result.organization_id.clone()}</p>
                                    <h3>
                                        <span class="result-title-text">{result.title.clone()}</span>
                                    </h3>
                                    <p class="result-id">{result.papra_document_id.clone()}</p>
                                    <p class="result-snippet">"Open the document in Papra to see the full content."</p>
                                </div>
                                <div class="result-meta">
                                    <span class="score">{format!("{:.0}% match", (1.0 - result.score).max(0.0) * 100.0)}</span>
                                    {result.source_url.clone().map(|url| view! { <a class="source-link" href=url target="_blank" rel="noreferrer">"Open in Papra ↗"</a> })}
                                </div>
                            </article>
                        </For>
                    </section>
                </Show>
            </Show>
        </main>
        <footer>"Papra Search · Private by design"</footer>
    }
}

const STYLE: &str = r#"
:root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, sans-serif; color: #18231f; background: #f6f8f5; }
* { box-sizing: border-box; }
body { margin: 0; min-width: 320px; background: radial-gradient(circle at 80% -20%, #dceee5 0, transparent 38rem), #f6f8f5; }
.topbar { max-width: 1120px; margin: auto; padding: 1.5rem 2rem; display: flex; justify-content: space-between; align-items: center; }
.brand { display: inline-flex; gap: .6rem; align-items: center; color: #18231f; text-decoration: none; font-weight: 750; letter-spacing: -.02em; }
.brand-mark { display: grid; place-items: center; width: 2rem; height: 2rem; border-radius: .7rem; color: white; background: #176b4d; font-size: 1.4rem; }
.shell { max-width: 820px; margin: 0 auto; padding: 5rem 2rem 7rem; }
.hero { max-width: 650px; margin-bottom: 3.5rem; }
.eyebrow, .result-org { margin: 0 0 .8rem; color: #176b4d; text-transform: uppercase; font-size: .72rem; font-weight: 800; letter-spacing: .12em; }
h1 { margin: 0; max-width: 700px; font-size: clamp(2.6rem, 7vw, 5rem); line-height: .98; letter-spacing: -.065em; }
.lede { max-width: 560px; margin: 1.5rem 0 0; color: #60716a; font-size: 1.15rem; line-height: 1.6; }
.button { border: 0; border-radius: .75rem; padding: .8rem 1.1rem; font: inherit; font-weight: 700; cursor: pointer; transition: transform .15s, background .15s; }
.button:hover { transform: translateY(-1px); }
.button:focus-visible, input:focus-visible, a:focus-visible { outline: 3px solid #91cbb1; outline-offset: 3px; }
.button-primary { color: white; background: #176b4d; }
.button-primary:hover { background: #0d573d; }
.button-primary:disabled { opacity: .65; cursor: wait; }
.button-quiet { color: #176b4d; background: #e5f0ea; }
.panel { padding: 2.5rem; border: 1px solid #dce5df; border-radius: 1.25rem; background: rgba(255,255,255,.78); box-shadow: 0 1.5rem 4rem rgba(25, 58, 44, .07); }
.sign-in-panel { text-align: center; }
.panel-icon { display: grid; place-items: center; width: 3rem; height: 3rem; margin: 0 auto 1rem; border-radius: 1rem; color: #176b4d; background: #e5f0ea; font-size: 1.4rem; }
h2 { margin: 0; font-size: 1.35rem; letter-spacing: -.03em; }
.panel p { color: #60716a; margin: .75rem auto 1.5rem; line-height: 1.5; }
.search-form label { display: block; margin-bottom: .6rem; font-weight: 750; }
.search-row { display: flex; gap: .7rem; }
input { width: 100%; min-width: 0; padding: .9rem 1rem; border: 1px solid #bdcbc3; border-radius: .75rem; color: inherit; background: white; font: inherit; }
.field-help { margin: .6rem 0 0; color: #78877f; font-size: .82rem; }
.status { display: flex; gap: .6rem; align-items: center; margin: 2rem 0; color: #176b4d; font-weight: 650; }
.spinner { width: 1rem; height: 1rem; border: 2px solid #c9dfd2; border-top-color: #176b4d; border-radius: 50%; animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.alert { margin-top: 1.5rem; padding: .9rem 1rem; border: 1px solid #e7b9b0; border-radius: .7rem; color: #8c3227; background: #fff3f0; }
.results { margin-top: 3rem; }
.results-heading { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 1rem; }
.results-heading span, .result-id { color: #78877f; font-size: .85rem; }
.result-card { display: flex; gap: 1.1rem; margin-top: .8rem; padding: 1.3rem 1.4rem; border: 1px solid #dce5df; border-radius: 1rem; background: white; align-items: flex-start; }
.result-thumb { flex: 0 0 4.25rem; height: 5.2rem; border-radius: .85rem; display: grid; place-items: center; color: #176b4d; background: #eaf3ee; border: 1px solid #dce5df; font-weight: 800; letter-spacing: .08em; }
.result-thumb-link { text-decoration: none; font-size: 1.05rem; }
.result-copy { min-width: 0; flex: 1; }
.result-card h3 { margin: 0; font-size: 1.1rem; }
.result-title-link { color: inherit; text-decoration: none; }
.result-title-link:hover { text-decoration: underline; }
.result-org { margin-bottom: .4rem; font-size: .65rem; }
.result-id { margin: .45rem 0 0; }
.result-snippet { margin: .7rem 0 0; color: #52625c; line-height: 1.5; font-size: .92rem; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }
.result-meta { display: flex; flex-direction: column; gap: .65rem; align-items: flex-end; white-space: nowrap; }
.score { color: #176b4d; font-size: .82rem; font-weight: 800; }
.source-link { color: #176b4d; font-size: .85rem; font-weight: 700; text-decoration: none; }
.empty { margin-top: 2rem; text-align: center; }
footer { padding: 2rem; color: #8b9891; text-align: center; font-size: .8rem; }
@media (max-width: 600px) { .topbar { padding: 1rem; } .shell { padding: 3rem 1rem 5rem; } .search-row, .result-card { flex-direction: column; } .search-row .button { width: 100%; } .result-thumb { width: 100%; height: 3.5rem; } .result-meta { flex-direction: row; align-items: center; justify-content: space-between; } }
"#;
