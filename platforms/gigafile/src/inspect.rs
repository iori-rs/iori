use fake_user_agent::get_chrome_rua;
use reqwest::{
    Client,
    header::{CONTENT_DISPOSITION, COOKIE, USER_AGENT},
};
use shiori_plugin::*;

use crate::client::GigafileClient;

pub struct GigafilePlugin;

impl ShioriPlugin for GigafilePlugin {
    fn name(&self) -> impl Future<Output = String> {
        async { "gigafile".to_string() }
    }

    fn version(&self) -> impl Future<Output = String> {
        async { "0.1.0".to_string() }
    }

    fn description(&self) -> impl Future<Output = Option<String>> {
        async { Some("Extracts raw download URL from Gigafile.".to_string()) }
    }

    async fn register(
        &self,
        mut registry: impl Registry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        registry.add_argument("giga-key", Some("key"), "[Gigafile] Download key");

        let regex = Regex::new(r"https://(\d+)\.gigafile\.nu/.*").unwrap();
        registry.register_inspector(regex, Box::new(GigafileInspector), PriorityHint::Normal);
        Ok(())
    }
}

struct GigafileInspector;

#[async_trait]
impl Inspect for GigafileInspector {
    async fn inspect(
        &self,
        url: &str,
        _captures: &regex::Captures,
        args: &dyn InspectorArguments,
    ) -> anyhow::Result<InspectResult> {
        let key = args.get_string("giga-key");
        let client = GigafileClient::new(key);
        let (url, cookie) = client.get_download_url(url.try_into()?).await?;

        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let response = client
            .get(&url)
            .header(COOKIE, &cookie)
            .header(USER_AGENT, get_chrome_rua())
            .send()
            .await?;
        let filename = response.headers().get(CONTENT_DISPOSITION).and_then(|v| {
            // attachment; filename="<filename>";
            let re = regex::bytes::Regex::new(r#"filename="([^"]+)""#).unwrap();
            let matched = re
                .captures(v.as_bytes())
                .and_then(|c| c.get(1).map(|m| m.as_bytes()))?;
            let filename = String::from_utf8(matched.to_vec()).ok()?;
            Some(filename)
        });
        drop(response);

        let filename = filename.map(|f| {
            let (name, ext) = f.rsplit_once('.').unwrap_or((&f, "raw"));
            (name.to_string(), ext.to_string())
        });
        let (title, ext) = match filename {
            Some((filename, ext)) => (Some(filename), ext),
            None => (None, "raw".to_string()),
        };

        Ok(InspectResult::Playlist(InspectPlaylist {
            title,
            playlist_url: url,
            playlist_type: PlaylistType::Raw(ext),
            headers: vec![format!("Cookie: {cookie}")],
            ..Default::default()
        }))
    }
}
