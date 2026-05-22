use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::danmaku::protocol::{
    data::{
        Chat, Enquete, OperatorComment,
        chat::{
            AccountStatus,
            modifier::{Color, ColorName, Font, Pos, Size},
        },
        enquete::Status,
    },
    service::edge::chunked_message::Meta,
};

#[derive(Deserialize, Debug)]
#[serde(tag = "type", content = "data", rename_all = "camelCase")]
pub enum WatchResponse {
    /// Ping message, should respond Pong
    Ping,
    ServerTime(WatchMessageServerTime),
    Seat(WatchMessageSeat),
    Stream(WatchMessageStream),
    MessageServer(WatchMessageMessageServer),
    Statistics(WatchMessageStatistics),
    EventState(WatchMessageEventState),
    Akashic(WatchMessageAkashic),
    Schedule(WatchMessageSchedule),
    AkashicMessageServer(WatchMessageAkashicMessageServer),
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WatchMessageServerTime {
    pub current_ms: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WatchMessageSeat {
    pub keep_interval_sec: u64,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WatchMessageStream {
    /// hls
    pub protocol: String,

    pub cookies: StreamCookies,

    /// super_high
    pub quality: String,
    /// ["abr", "super_high", "high", "normal", "low", "super_low", "audio_high"]
    pub available_qualities: Vec<String>,

    /// sync json uri
    pub sync_uri: String,
    /// HLS m3u8 uri
    pub uri: String,
}

#[derive(Deserialize, Debug)]
pub struct StreamCookies(#[serde(default)] Vec<WatchStreamCookie>);

impl StreamCookies {
    pub fn into_cookies(self) -> Vec<String> {
        self.0
            .into_iter()
            .map(|c| {
                let mut cookie = format!("{}={}; Domain={}", c.name, c.value, c.domain);
                if let Some(path) = c.path {
                    cookie.push_str(&format!("; Path={path}"));
                }
                if let Some(expires) = c.expires {
                    cookie.push_str(&format!("; Expires={expires}"));
                }
                if c.secure {
                    cookie.push_str("; Secure");
                }
                cookie
            })
            .collect()
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WatchStreamCookie {
    pub name: String,
    pub value: String,

    pub domain: String,
    pub path: Option<String>,
    pub expires: Option<String>,
    #[serde(default)]
    pub secure: bool,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WatchMessageMessageServer {
    pub hashed_user_id: Option<String>,
    pub view_uri: String,
    pub vpos_base_time: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WatchMessageStatistics {
    pub viewers: Option<i32>,
    pub comments: Option<i32>,
    pub ad_points: Option<i32>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WatchMessageEventState {
    pub comment_state: WatchMessageEventStateCommentState,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WatchMessageEventStateCommentState {
    pub layout: String, // normal
    pub locked: bool,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WatchMessageAkashic {
    pub content_url: Option<String>,
    pub log_server_url: Option<String>,
    pub play_id: Option<String>,
    pub player_id: Option<String>,
    pub status: String,
    pub token: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WatchMessageSchedule {
    pub begin: String,
    pub end: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WatchMessageAkashicMessageServer {
    pub view_uri: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum DanmakuResponse {
    Ping(DanmakuMessagePing),
    Thread(DanmakuMessageThread),
    Chat(DanmakuMessageChat),
}

#[derive(Deserialize, Debug)]
pub struct DanmakuMessagePing {
    pub content: String,
}

#[derive(Deserialize, Debug)]
pub struct DanmakuMessageThread {
    pub last_res: Option<u64>,
    pub revision: i32,
    pub resultcode: i32,
    pub server_time: u64,
    pub thread: String,
    pub ticket: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct DanmakuMessageChat {
    // {
    //   "thread": "M.V67enstLPeSLVO0U1lcbDA",
    //   "no": 6,
    //   "vpos": 437,
    //   "date": 1693485004,
    //   "date_usec": 565330,
    //   "mail": "184",
    //   "user_id": "-Br5e0CRUyNpHCL3i4SrPOWyqVU",
    //   "premium": 1,
    //   "anonymity": 1,
    //   "content": "(*>△<)＜ ナーンナーンっっ"
    // }
    //
    // {
    //   "thread": "M.V67enstLPeSLVO0U1lcbDA",
    //   "no": 95,
    //   "vpos": 7955,
    //   "date": 1693485081,
    //   "date_usec": 566853,
    //   "name": "インパクト",
    //   "user_id": "12015520",
    //   "premium": 24,
    //   "content": "かーっ！"
    // }
    // {
    //     "chat": {
    //         "thread": "M.YDYUsM77eTeeX0zyRfJEIg",
    //         "vpos": 241,
    //         "date": 1693482605,
    //         "date_usec": 980236,
    //         "mail": "184",
    //         "user_id": "n20sthjgLwnk5_r25NbrtX8XnHU",
    //         "premium": 1,
    //         "anonymity": 1,
    //         "content": "さいまえ"
    //     }
    // },
    pub thread: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no: Option<i64>,
    // vpos might be negative:
    // {"chat":{"thread":"M.V67enstLPeSLVO0U1lcbDA","no":1,"vpos":-298283036,"date":1690502169,"date_usec":660934,"mail":"184","user_id":"zQVo171K_fu_CsvU99gO305dOU4","premium":3,"anonymity":1,"content":"/trialpanel on 1"}}
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpos: Option<i64>,

    pub date: u64,
    pub date_usec: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail: Option<String>,
    pub user_id: DanmakuUserId,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub premium: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anonymity: Option<u8>,

    pub content: String,
}

impl PartialOrd for DanmakuMessageChat {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // compare date first, then vpos
        Some(self.date.cmp(&other.date).then(self.vpos.cmp(&other.vpos)))
    }
}

impl DanmakuMessageChat {
    pub fn from_chat(chat: Chat, meta: &Meta) -> Self {
        let time = meta.at.unwrap().normalized();

        let mut commands = Vec::new();
        if chat.raw_user_id() == 0 {
            commands.push("184".to_string());
        }
        if let Some(modifier) = chat.modifier {
            match modifier.position() {
                Pos::Naka => {}
                pos => commands.push(pos.as_str_name().to_string()),
            }
            match modifier.size() {
                Size::Medium => {}
                size => commands.push(size.as_str_name().to_string()),
            }
            if let Some(color) = modifier.color {
                match color {
                    Color::NamedColor(named) => {
                        let name = ColorName::try_from(named).unwrap();
                        match name {
                            ColorName::White => {}
                            name => commands.push(name.as_str_name().to_string()),
                        }
                    }
                    Color::FullColor(color) => {
                        let r = color.r;
                        let g = color.g;
                        let b = color.b;
                        commands.push(format!("#{:02x}{:02x}{:02x}", r, g, b));
                    }
                }
            }
            match modifier.font() {
                Font::Defont => {}
                font => commands.push(font.as_str_name().to_string()),
            }
        }

        Self {
            thread: None,
            no: Some(chat.no as i64),
            vpos: Some(chat.vpos as i64),
            date: time.seconds as u64,
            date_usec: time.nanos as u64 / 1000,
            name: chat.name.clone(),
            mail: if commands.is_empty() {
                None
            } else {
                Some(commands.join(" "))
            },
            user_id: if chat.raw_user_id() > 0 {
                DanmakuUserId::new(chat.raw_user_id().to_string())
            } else {
                DanmakuUserId::new(chat.hashed_user_id().to_string())
            },
            premium: if let AccountStatus::Premium = chat.account_status() {
                Some(1)
            } else {
                None
            },
            anonymity: if chat.raw_user_id() == 0 {
                Some(1)
            } else {
                None
            },
            content: chat.content,
        }
    }

    pub fn from_operator_comment(
        chat: OperatorComment,
        meta: &Meta,
        start_time: Option<i64>,
    ) -> Self {
        let time = meta.at.unwrap().normalized();

        let mut commands = Vec::new();
        commands.push("184".to_string());
        if let Some(modifier) = chat.modifier {
            match modifier.position() {
                Pos::Naka => {}
                pos => commands.push(pos.as_str_name().to_string()),
            }
            match modifier.size() {
                Size::Medium => {}
                size => commands.push(size.as_str_name().to_string()),
            }
            if let Some(color) = modifier.color {
                match color {
                    Color::NamedColor(named) => {
                        let name = ColorName::try_from(named).unwrap();
                        match name {
                            ColorName::White => {}
                            name => commands.push(name.as_str_name().to_string()),
                        }
                    }
                    Color::FullColor(color) => {
                        let r = color.r;
                        let g = color.g;
                        let b = color.b;
                        commands.push(format!("#{:02x}{:02x}{:02x}", r, g, b));
                    }
                }
            }
            match modifier.font() {
                Font::Defont => {}
                font => commands.push(font.as_str_name().to_string()),
            }
        }

        Self {
            thread: None,
            no: None,
            vpos: start_time.map(|s| (time.seconds - s) * 100),
            date: time.seconds as u64,
            date_usec: time.nanos as u64 / 1000,
            name: chat.name.clone(),
            mail: if commands.is_empty() {
                None
            } else {
                Some(commands.join(" "))
            },
            user_id: DanmakuUserId::OPERATOR,
            premium: Some(3),
            anonymity: Some(1),
            content: chat.content,
        }
    }

    pub fn from_enquete(enquete: Enquete, meta: &Meta, start_time: Option<i64>) -> Self {
        let time = meta.at.unwrap().normalized();

        let mut commands = Vec::new();
        commands.push("184".to_string());

        // {"thread":"M.KyX3o2wVpNJurP1jzo6ytQ","vpos":407083,"date":1704373070,"date_usec":839544,"mail":"184","user_id":"ETACr1rb2bHQ4naN57Zp61SAShw","premium":3,"anonymity":1,"content":"/vote showresult per 977 15 3 2 3"}
        Self {
            thread: None,
            no: None,
            vpos: start_time.map(|s| (time.seconds - s) * 100),
            date: time.seconds as u64,
            date_usec: time.nanos as u64 / 1000,
            name: None,
            mail: Some("184".to_string()),
            user_id: DanmakuUserId::OPERATOR,
            premium: Some(3),
            anonymity: Some(1),
            content: match enquete.status() {
                // /vote start 本日の番組はいかがでしたか？ とても良かった まぁまぁ良かった ふつうだった あまり良くなかった 良くなかった
                Status::Poll => format!(
                    "/vote start {}",
                    shlex::try_join(
                        vec![enquete.question.as_str()]
                            .into_iter()
                            .chain(enquete.choices.iter().map(|c| c.description.as_str()))
                    )
                    .expect("Vote question and choices should not contain invalid characters")
                ),
                // /vote showresult per 977 15 3 2 3
                Status::Result => format!(
                    "/vote showresult per {}",
                    enquete
                        .choices
                        .iter()
                        .map(|c| c.per_mille.unwrap_or(0).to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
                // /vote stop
                Status::Closed => "/vote stop".to_string(),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[serde(transparent)]
pub struct DanmakuUserId(Cow<'static, str>);

impl DanmakuUserId {
    pub const OPERATOR: Self = Self(Cow::Borrowed("operator"));

    pub fn new(id: String) -> Self {
        Self(Cow::Owned(id))
    }

    pub fn is_operator(&self) -> bool {
        self == &Self::OPERATOR
    }
}
