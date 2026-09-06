use leptos::prelude::*;

const UI_SCRIPT: &str = r#"
(() => {
  const loginPanel = document.getElementById("login-panel");
  const searchPanel = document.getElementById("search-panel");
  const signIn = document.getElementById("sign-in");
  const searchForm = document.getElementById("search-form");
  const queryInput = document.getElementById("query");
  const status = document.getElementById("status");
  const results = document.getElementById("results");
  let idToken;

  const setStatus = (message, kind = "") => {
    status.textContent = message;
    status.className = kind ? `status ${kind}` : "status";
  };

  const showAuthenticated = () => {
    loginPanel.hidden = true;
    searchPanel.hidden = false;
    queryInput.focus();
  };

  const showUnauthenticated = () => {
    idToken = undefined;
    loginPanel.hidden = false;
    searchPanel.hidden = true;
    queryInput.value = "";
    results.replaceChildren();
    signIn.focus();
  };

  const finishLogin = (popup) => {
    const timer = window.setInterval(() => {
      if (popup.closed) {
        window.clearInterval(timer);
        setStatus("Sign-in was cancelled.", "error");
        return;
      }
      let body;
      try {
        body = popup.document.body?.textContent?.trim();
      } catch (_) {
        // The popup is on Google's origin until the callback completes.
        return;
      }
      if (!body) return;
      let response;
      try {
        response = JSON.parse(body);
      } catch (_) {
        return;
      }
      try {
        if (typeof response.id_token !== "string" || response.id_token.length === 0) {
          throw new Error("The provider did not return an ID token.");
        }
        idToken = response.id_token;
        window.clearInterval(timer);
        popup.close();
        setStatus("");
        showAuthenticated();
      } catch (error) {
        window.clearInterval(timer);
        popup.close();
        setStatus(error.message || "Sign-in failed. Please try again.", "error");
      }
    }, 100);
  };

  signIn.addEventListener("click", () => {
    setStatus("Opening Google sign-in…");
    const popup = window.open(
      "/oidc/login",
      "papra-google-sign-in",
      "popup,width=520,height=650,resizable=yes,scrollbars=yes"
    );
    if (!popup) {
      setStatus("Your browser blocked the sign-in window. Allow pop-ups and try again.", "error");
      return;
    }
    popup.focus();
    finishLogin(popup);
  });

  const renderResults = (items) => {
    results.replaceChildren();
    if (items.length === 0) {
      setStatus("No matching documents found.", "empty");
      return;
    }
    setStatus(`${items.length} result${items.length === 1 ? "" : "s"} found.`);
    for (const item of items) {
      const card = document.createElement("article");
      card.className = "result-card";
      const title = document.createElement("h3");
      title.textContent = item.title || "Untitled document";
      card.append(title);
      const details = document.createElement("p");
      details.className = "result-details";
      const score = Number(item.score);
      details.textContent = `Organization: ${item.organization_id || "unknown"} · Similarity score: ${
        Number.isFinite(score) ? score.toFixed(3) : "unavailable"
      }`;
      card.append(details);
      if (typeof item.source_url === "string" && item.source_url.length > 0) {
        const link = document.createElement("a");
        link.href = item.source_url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = "Open in Papra";
        card.append(link);
      }
      results.append(card);
    }
  };

  searchForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const query = queryInput.value.trim();
    if (query.length === 0 || [...query].length > 1000) {
      setStatus("Enter a query between 1 and 1,000 characters.", "error");
      queryInput.focus();
      return;
    }
    if (!idToken) {
      showUnauthenticated();
      window.location.assign("/oidc/login");
      return;
    }
    searchForm.querySelector("button").disabled = true;
    setStatus("Searching…", "loading");
    results.replaceChildren();
    try {
      const authHeader = ["Bearer", idToken].join(" ");
      const response = await fetch(`/api/search?q=${encodeURIComponent(query)}&limit=20`, {
        headers: { Authorization: authHeader, Accept: "application/json" }
      });
      if (response.status === 401) {
        showUnauthenticated();
        window.location.assign("/oidc/login");
        return;
      }
      if (!response.ok) {
        throw new Error("The search service is unavailable. Please try again.");
      }
      const payload = await response.json();
      renderResults(Array.isArray(payload.results) ? payload.results : []);
    } catch (error) {
      if (error.name !== "AbortError") {
        setStatus(error.message || "Search failed. Please try again.", "error");
      }
    } finally {
      searchForm.querySelector("button").disabled = false;
    }
  });
})();
"#;

#[component]
pub fn App() -> impl IntoView {
    view! {
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <title>Papra Vector Search</title>
                <style>
                    r#"
                    :root { color-scheme: light; font-family: system-ui, sans-serif; color: #172033; background: #f5f7fb; }
                    * { box-sizing: border-box; }
                    body { margin: 0; }
                    main { width: min(100% - 2rem, 52rem); margin: 0 auto; padding: 4rem 0; }
                    .intro { margin-bottom: 2rem; }
                    h1 { margin: 0 0 .5rem; font-size: clamp(2rem, 5vw, 3rem); }
                    .muted { color: #526078; }
                    .panel, .result-card { background: #fff; border: 1px solid #dce2ed; border-radius: .75rem; box-shadow: 0 8px 24px #1720330d; }
                    .panel { padding: 1.5rem; }
                    label { display: block; font-weight: 650; margin-bottom: .5rem; }
                    input { width: 100%; border: 1px solid #8b98ad; border-radius: .45rem; font: inherit; padding: .75rem; }
                    input:focus-visible, button:focus-visible, a:focus-visible { outline: 3px solid #6b8afd; outline-offset: 2px; }
                    button { border: 0; border-radius: .45rem; background: #3158d8; color: #fff; cursor: pointer; font: inherit; font-weight: 650; padding: .75rem 1rem; }
                    button:hover { background: #2748b6; }
                    button:disabled { cursor: wait; opacity: .65; }
                    form { display: grid; gap: .75rem; }
                    .status { min-height: 1.5rem; margin: 1rem 0; color: #526078; }
                    .status.error { color: #a52a2a; }
                    .status.empty { color: #526078; }
                    .status.loading { color: #3158d8; }
                    #results { display: grid; gap: 1rem; }
                    .result-card { padding: 1rem 1.25rem; }
                    .result-card h3 { margin: 0 0 .5rem; overflow-wrap: anywhere; }
                    .result-details { color: #526078; font-size: .9rem; margin: 0 0 .75rem; }
                    .result-card a { color: #3158d8; font-weight: 650; }
                    [hidden] { display: none !important; }
                    "#
                </style>
            </head>
            <body>
                <main id="app">
                    <header class="intro">
                        <p class="muted">Papra</p>
                        <h1>Find your documents</h1>
                        <p class="muted">Search your organization&apos;s Papra documents by meaning.</p>
                    </header>
                    <section id="login-panel" class="panel" aria-labelledby="login-heading">
                        <h2 id="login-heading">Sign in to search</h2>
                        <p class="muted">Use your authorized Google account to continue.</p>
                        <button id="sign-in" type="button">Continue with Google</button>
                    </section>
                    <section id="search-panel" class="panel" aria-labelledby="search-heading" hidden>
                        <h2 id="search-heading">Search documents</h2>
                        <form id="search-form">
                            <label for="query">Search query</label>
                            <input id="query" name="q" type="search" maxlength="1000" autocomplete="off"
                                placeholder="Try “project kickoff notes”"/>
                            <button type="submit">Search</button>
                        </form>
                    </section>
                    <p id="status" class="status" role="status" aria-live="polite"></p>
                    <section id="results" aria-label="Search results"></section>
                </main>
                <script inner_html=UI_SCRIPT></script>
            </body>
        </html>
    }
}
