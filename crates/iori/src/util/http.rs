use std::{ops::Deref, sync::Arc};

use reqwest::{Client, ClientBuilder, IntoUrl};
use reqwest_cookie_store::{CookieStore, CookieStoreMutex};

pub use reqwest;

#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    cookies_store: Arc<CookieStoreMutex>,
}

impl HttpClient {
    pub fn new(builder: ClientBuilder) -> Self {
        let cookies_store = Arc::new(CookieStoreMutex::new(CookieStore::default()));
        let client = builder
            .cookie_provider(cookies_store.clone())
            .build()
            .unwrap();

        Self {
            client,
            cookies_store,
        }
    }

    pub fn add_cookies(&self, cookies: Vec<String>, url: impl IntoUrl) {
        if cookies.is_empty() {
            return;
        }

        let url = url.into_url().unwrap();
        let mut lock = self.cookies_store.lock().unwrap();
        for cookie in cookies {
            _ = lock.parse(&cookie, &url);
        }
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        let cookies_store = Arc::new(CookieStoreMutex::new(CookieStore::default()));
        let client = Client::builder()
            .cookie_provider(cookies_store.clone())
            .build()
            .unwrap();

        Self {
            client,
            cookies_store,
        }
    }
}

impl Deref for HttpClient {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}
