/// Implementation of DASH timeline
///
/// References:
/// - [DASH-IF implementation guidelines: restricted timing model](https://dashif.org/Guidelines-TimingModel)
/// - [MPEG-DASH](https://www.mpeg.org/standards/MPEG-DASH/)
/// - https://github.com/nilaoda/N_m3u8DL-RE/blob/ad7136ae64379cb5aae09a6ada2b788c7030c917/src/N_m3u8DL-RE.Parser/Extractor/DASHExtractor2.cs
/// - https://github.com/emarsden/dash-mpd-rs/blob/main/src/fetch.rs
use chrono::{DateTime, Duration, TimeDelta, Utc};
use dash_mpd::{
    AdaptationSet, MPD, Period, Representation, SegmentBase, SegmentList, SegmentTemplate,
};
use url::Url;

use std::sync::Arc;

use crate::{
    ByteRange, HttpClient, InitialSegment, IoriError, IoriResult, SegmentType,
    dash::{
        segment::DashSegment,
        template::{Template, TemplateUrl},
        url::{UriExt, is_absolute_url, merge_baseurls, parse_media_range},
    },
    decrypt::IoriKey,
};

use super::{clock::Clock, selector::best_representation};

/// https://dashif.org/Guidelines-TimingModel/#mpd-general-timeline
///
/// > The MPD defines the MPD timeline of a DASH presentation, which serves as the baseline
/// > for all scheduling decisions made during playback and establishes the relative timing
/// > of periods and media segments. The MPD timeline informs DASH clients on when it can
/// > download and present which media segments. The contents of an MPD are a promise by a
/// > DASH service to make specific media segments available during specific time spans
/// > described by the MPD timeline.
///
/// > Values on the MPD timeline are all ultimately relative to the zero point of the MPD
/// > timeline, though possibly through several layers of indirection (e.g. period A is
/// > relative to period B, which is relative to the zero point).
///
/// > The following MPD elements are most relevant to locating and scheduling the media samples:
///
/// > 1. The MPD describes consecutive periods which map data onto the MPD timeline.
///
/// > 2. Each period describes of one or more representations, each of which provides media samples
/// > inside a sequence of media segments located via segment references. Representations contain
/// > independent sample timelines that are mapped to the time span on the MPD timeline that belongs
/// > to the period.
///
/// > 3. Representations within a period are grouped into adaptation sets, which associate related
/// > representations and decorate them with metadata.
pub struct MPDTimeline {
    client: HttpClient,

    presentation: DashPresentation,

    /// An MPD defines an ordered list of one or more consecutive non-overlapping periods ([DASH] 5.3.2).
    /// A period is both a time span on the MPD timeline and a definition of the data to be presented
    /// during this time span. Period timing is relative to the zero point of the MPD timeline, though
    /// often indirectly (being relative to the previous period).
    periods: Vec<DashPeriod>,

    presentation_delay: TimeDelta,
    time_shift_buffer_depth: Option<TimeDelta>,
}

impl MPDTimeline {
    pub async fn from_mpd(mpd: MPD, mpd_url: Option<&Url>, client: HttpClient) -> IoriResult<Self> {
        let mut presentation = DashPresentation::from_mpd(&mpd);
        presentation.sync_time(&mpd, client.clone()).await?;

        let mpd_base_url = mpd.base_url.first().map(|u| u.base.as_str());
        let base_url = match (mpd_base_url, mpd_url) {
            (Some(mpd_base_url), Some(mpd_url)) => merge_baseurls(mpd_url, mpd_base_url)?,
            (None, Some(mpd_url)) => mpd_url.clone(),
            (Some(mpd_base_url), None) if is_absolute_url(mpd_base_url) => {
                Url::parse(mpd_base_url)?
            }
            _ => return Err(IoriError::MpdParsing("Invalid base url".to_string())),
        };

        let mut periods: Vec<DashPeriod> = Vec::with_capacity(mpd.periods.len());
        for mut period in mpd.periods {
            if presentation.is_static() && periods.is_empty() && period.start.is_none() {
                period.start = Some(std::time::Duration::ZERO);
            }

            let last_mut = periods.last_mut();
            let period = DashPeriod::from_mpd(&base_url, period, last_mut)?;
            periods.push(period);
        }

        Ok(Self {
            client,
            presentation,
            periods,
            time_shift_buffer_depth: mpd
                .timeShiftBufferDepth
                .map(TimeDelta::from_std)
                .transpose()?,
            presentation_delay: mpd
                .suggestedPresentationDelay
                .map(TimeDelta::from_std)
                .transpose()?
                .unwrap_or_else(TimeDelta::zero),
        })
    }

    pub fn is_static(&self) -> bool {
        self.presentation.is_static()
    }

    pub fn is_dynamic(&self) -> bool {
        self.presentation.is_dynamic()
    }

    /// Return all segments available in the dash timeline > the given time
    ///
    /// Note that this function can not handle segment time at UNIX_EPOCH
    pub async fn segments_since(
        &self,
        since: Option<DateTime<Utc>>,
        key: Option<Arc<IoriKey>>,
    ) -> IoriResult<(Vec<DashSegment>, Option<DateTime<Utc>>)> {
        let include_since = since.is_none();
        let since = since.unwrap_or_default();

        // https://dashif.org/Guidelines-TimingModel/#availability-window
        // 1. Let _now_ be the current wall clock time according to the wall clock.
        let now: DateTime<Utc> = self.presentation.now();
        // 2. Let _AvailabilityWindowStart_ be _now_ - `MPD@timeShiftBufferDepth`.
        let availability_window_start = match self.time_shift_buffer_depth {
            Some(buffer_depth) => now - buffer_depth,
            // If `MPD@timeShiftBufferDepth` is not defined, let _AvailabilityWindowStart_ be the effective availability start time.
            None => self.presentation.zero_point(),
        };

        let mut last_time = None;
        let mut segments = Vec::new();

        for period in self.periods.iter() {
            let (effective_time_shift_buffer_start, effective_time_shift_buffer_end) = {
                // 3. Let _TotalAvailabilityTimeOffset_ be the sum of all `@availabilityTimeOffset` values that apply to the adaptation set,
                // either via _SegmentBase_, _SegmentTemplate_ or BaseURL elements ([DASH] 5.3.9.5.3).
                let total_availability_time_offset = period
                    .adaptation_sets
                    .iter()
                    .map(|a| a.representation.availability_time_offset())
                    .sum::<TimeDelta>();
                // 4. The availability window is the time span from _AvailabilityWindowStart_ to _now_ + _TotalAvailabilityTimeOffset_.
                let availability_window_end = now + total_availability_time_offset;

                // The effective time shift buffer is the time span from the start of the time shift buffer to now - PresentationDelay.
                // Services SHALL NOT define a value for MPD@suggestedPresentationDelay that results in an effective time shift buffer of negative or zero duration.
                let effective_time_shift_buffer_start = availability_window_start;
                let effective_time_shift_buffer_end =
                    availability_window_end - self.presentation_delay;

                (
                    effective_time_shift_buffer_start,
                    effective_time_shift_buffer_end,
                )
            };
            // override effective_time_shift_buffer_start to be >= since
            let effective_time_shift_buffer_start = effective_time_shift_buffer_start.max(since);

            let is_before_effective_time_shift_buffer_start = move |time: DateTime<Utc>| {
                if include_since {
                    time < effective_time_shift_buffer_start
                } else {
                    time <= effective_time_shift_buffer_start
                }
            };

            // skip periods ends before <since>
            if let Some(duration) = period.duration
                && period.start_time + duration < since
            {
                continue;
            }

            // FIXME: do not use adaption index as stream id
            for (stream_id, adaptation_set) in period.adaptation_sets.iter().enumerate() {
                match &adaptation_set.representation {
                    DashRepresentation::IndexedAddressing(_) => todo!(),
                    DashRepresentation::ExplicitAddressing {
                        initialization,
                        media,
                        start_number,
                        sample_timeline,
                        id,
                        bandwidth,
                        mime_type,
                        timeline_segments,
                        ..
                    } => {
                        let mut start_time_pts = timeline_segments
                            .first()
                            .and_then(|r| r.time)
                            .unwrap_or_default();
                        let mut number = *start_number;

                        let mut initial_segment = None;

                        for timeline_segment in timeline_segments {
                            if let Some(time) = timeline_segment.time {
                                start_time_pts = time;
                            }
                            let duration_pts = timeline_segment.duration;
                            let repeat_count = timeline_segment.repeat_count.unwrap_or(0);

                            // TODO: support negative repeat count
                            // The value of S@r is nonnegative, except for the last S element which MAY have a negative
                            // value in S@r ([DASH] 5.3.9.6), indicating that the repeated segment references continue
                            // indefinitely up to a media segment that either ends at or overlaps the period end point.

                            let mut template = Template::new();
                            template
                                .insert_optional(Template::REPRESENTATION_ID, id.clone())
                                .insert(Template::BANDWIDTH, bandwidth.unwrap_or(0).to_string());

                            // > Only additional segment references are counted by @r, so S@r=5 indicates a total of
                            // > 6 consecutive media segments with the same duration.
                            for _ in 0..=repeat_count {
                                let segment_start_point = start_time_pts;
                                start_time_pts += duration_pts;
                                let segment_number = number;
                                number += 1;

                                let segment_start_time = sample_timeline
                                    .map_time(period.start_time, segment_start_point)?;

                                if segment_start_time > effective_time_shift_buffer_end {
                                    break;
                                }
                                if let Some(period_duration) = period.duration
                                    && segment_start_time >= period.start_time + period_duration
                                {
                                    break;
                                }
                                if is_before_effective_time_shift_buffer_start(segment_start_time) {
                                    continue;
                                }
                                last_time = Some(segment_start_time);

                                template
                                    .insert(Template::NUMBER, segment_number.to_string())
                                    .insert(Template::TIME, segment_start_point.to_string());

                                let segment_url = media.resolve(&template);
                                let segment_url = Url::parse(&segment_url)?;
                                let segment_filename = segment_url
                                    .filename()
                                    .unwrap_or(format!(
                                        "{}_{segment_number}.m4s",
                                        id.as_deref().unwrap_or("s"),
                                    ))
                                    .to_string();

                                if initial_segment.is_none() {
                                    if let Some(initialization) = initialization {
                                        let url = initialization.resolve(&template);
                                        let data =
                                            self.client.get(url).send().await?.bytes().await?;
                                        initial_segment = Some(InitialSegment::Encrypted(
                                            Arc::new(data.to_vec()),
                                        ));
                                    } else {
                                        initial_segment = Some(InitialSegment::None);
                                    }
                                }

                                segments.push(DashSegment {
                                    url: segment_url,
                                    filename: segment_filename,
                                    r#type: adaptation_set.content_type.as_ref().map_or_else(
                                        || SegmentType::from_mime_type(mime_type.as_deref()),
                                        |r| r.to_segment_type(),
                                    ),
                                    initial_segment: initial_segment.clone().unwrap(),
                                    key: key.clone(),
                                    byte_range: None,
                                    sequence: 0,
                                    stream_id: stream_id as u64,
                                    time: Some(segment_start_point),
                                });
                            }
                        }
                    }
                    DashRepresentation::SimpleAddressing {
                        initialization,
                        media,
                        start_number,
                        sample_timeline,
                        duration,
                        id,
                        bandwidth,
                        mime_type,
                        // TODO: support ept_delta
                        ept_delta: _ept_delta,
                        ..
                    } => {
                        let mut number = if period.start_time < effective_time_shift_buffer_start {
                            let time_since_period_start = (effective_time_shift_buffer_start
                                - period.start_time)
                                .as_seconds_f64();
                            let segment_number_since_period_start =
                                (time_since_period_start / duration) as u64;

                            start_number + segment_number_since_period_start
                        } else {
                            *start_number
                        };

                        let mut template = Template::new();
                        template
                            .insert_optional(Template::REPRESENTATION_ID, id.clone())
                            .insert(Template::BANDWIDTH, bandwidth.unwrap_or(0).to_string());

                        let mut initial_segment = None;

                        loop {
                            let segment_number = number;
                            number += 1;

                            let segment_start_point =
                                ((segment_number - start_number) as f64 * duration) as u64;
                            let segment_start_time =
                                sample_timeline.map_time(period.start_time, segment_start_point)?;

                            if segment_start_time > effective_time_shift_buffer_end {
                                break;
                            }
                            if let Some(period_duration) = period.duration
                                && (segment_start_time - period.start_time) >= period_duration
                            {
                                break;
                            }
                            if is_before_effective_time_shift_buffer_start(segment_start_time) {
                                continue;
                            }

                            last_time = Some(segment_start_time);

                            template
                                .insert(Template::NUMBER, segment_number.to_string())
                                .insert(Template::TIME, segment_start_point.to_string());

                            let segment_url = media.resolve(&template);
                            let segment_url = Url::parse(&segment_url)?;
                            let segment_filename = segment_url
                                .filename()
                                .unwrap_or(format!(
                                    "{}_{segment_number}.m4s",
                                    id.as_deref().unwrap_or("s"),
                                ))
                                .to_string();

                            if initial_segment.is_none() {
                                if let Some(initialization) = initialization {
                                    let url = initialization.resolve(&template);
                                    let data = self.client.get(url).send().await?.bytes().await?;
                                    initial_segment =
                                        Some(InitialSegment::Encrypted(Arc::new(data.to_vec())));
                                } else {
                                    initial_segment = Some(InitialSegment::None);
                                }
                            }

                            segments.push(DashSegment {
                                url: segment_url,
                                filename: segment_filename,
                                r#type: adaptation_set.content_type.as_ref().map_or_else(
                                    || SegmentType::from_mime_type(mime_type.as_deref()),
                                    |r| r.to_segment_type(),
                                ),
                                initial_segment: initial_segment.clone().unwrap(),
                                key: key.clone(),
                                byte_range: None,
                                sequence: 0,
                                stream_id: stream_id as u64,
                                time: Some(segment_start_point),
                            });
                        }
                    }
                    DashRepresentation::SegmentList {
                        initialization,
                        segment_items,
                        duration,
                        sample_timeline,
                        mime_type,
                    } => {
                        tracing::warn!(
                            "SegmentList support is experimental and may not work as expected."
                        );

                        let initial_segment = if let Some(initialization) = initialization {
                            InitialSegment::Encrypted(Arc::new(
                                self.client
                                    .get(initialization.url.clone())
                                    // TODO: support range
                                    .send()
                                    .await?
                                    .bytes()
                                    .await?
                                    .to_vec(),
                            ))
                        } else {
                            InitialSegment::None
                        };

                        let mut start_time_pts = 0_u64;

                        for segment in segment_items.iter() {
                            let segment_start_point = start_time_pts;
                            start_time_pts += duration;

                            let segment_start_time =
                                sample_timeline.map_time(period.start_time, segment_start_point)?;

                            if segment_start_time > effective_time_shift_buffer_end {
                                break;
                            }
                            if let Some(period_duration) = period.duration
                                && segment_start_time >= period.start_time + period_duration
                            {
                                break;
                            }
                            if is_before_effective_time_shift_buffer_start(segment_start_time) {
                                continue;
                            }

                            let segment_filename = segment
                                .url
                                .filename()
                                .unwrap_or("data.m4s".to_string())
                                .to_string();

                            segments.push(DashSegment {
                                url: segment.url.clone(),
                                filename: segment_filename,
                                r#type: adaptation_set.content_type.as_ref().map_or_else(
                                    || SegmentType::from_mime_type(mime_type.as_deref()),
                                    |r| r.to_segment_type(),
                                ),
                                initial_segment: initial_segment.clone(),
                                key: key.clone(),
                                byte_range: segment.range.clone(),
                                sequence: 0,
                                stream_id: stream_id as u64,
                                time: Some(segment_start_point),
                            });
                        }
                    }
                }
            }
        }

        Ok((segments, last_time))
    }

    /// Sync clock for internal clock
    pub async fn sync_time(&mut self, mpd: &MPD) -> IoriResult<()> {
        self.presentation.sync_time(mpd, self.client.clone()).await
    }

    pub async fn update_mpd(&mut self, mpd: MPD, mpd_url: &Url) -> IoriResult<()> {
        let mpd_base_url = mpd.base_url.first().map(|u| u.base.as_str());
        let base_url = match mpd_base_url {
            Some(mpd_base_url) => merge_baseurls(mpd_url, mpd_base_url)?,
            None => mpd_url.clone(),
        };

        self.sync_time(&mpd).await.unwrap();

        let mut periods: Vec<DashPeriod> = Vec::with_capacity(mpd.periods.len());
        for period in mpd.periods {
            let last_mut = periods.last_mut();
            let period = DashPeriod::from_mpd(&base_url, period, last_mut)?;
            periods.push(period);
        }
        self.periods = periods;

        Ok(())
    }
}

/// There exist two types of DASH presentations, indicated by MPD@type [DASH]:
pub enum DashPresentation {
    /// In a a static presentation (`MPD@type="static"`) any media segment may be
    /// presented at any time. The DASH client is in complete control over what
    /// content is presented when and the entire presentation is available at any time.
    Static,
    /// In a dynamic presentation (`MPD@type="dynamic"`) the MPD timeline is mapped to wall
    /// clock time, with each media segment on the MPD timeline intended to be presented at
    /// a specific moment in time (with some client-chosen time shift allowed).
    ///
    /// - Furthermore, media segments may become available and cease to be available with the passage of time.
    /// - The MPD may change over time, enabling the structure of the presentation to change over time (e.g.
    ///   when a new title in the presentation is offered with a different set of languages).
    Dynamic {
        clock: Clock,
        /// In a dynamic presentation, the zero point of the MPD timeline is the mapped to the point in
        /// wall clock time indicated by the effective availability start time, which is formed by taking
        /// `MPD@availabilityStartTime` and applying any LeapSecondInformation offset ([DASH] 5.3.9.5 and 5.13).
        zero_point: DateTime<Utc>,
    },
}

impl DashPresentation {
    pub fn from_mpd(mpd: &MPD) -> Self {
        match mpd.mpdtype.as_deref() {
            Some("dynamic") => Self::Dynamic {
                clock: Clock::new(),
                zero_point: mpd.availabilityStartTime.unwrap_or(DateTime::UNIX_EPOCH),
            },
            _ => Self::Static,
        }
    }

    pub async fn sync_time(&mut self, mpd: &MPD, client: HttpClient) -> IoriResult<()> {
        if let DashPresentation::Dynamic { clock, .. } = self {
            clock.sync(mpd, client).await?;
        }

        Ok(())
    }

    pub fn now(&self) -> DateTime<Utc> {
        if let DashPresentation::Dynamic { clock, .. } = self {
            clock.now()
        } else {
            Utc::now()
        }
    }

    pub fn zero_point(&self) -> DateTime<Utc> {
        if let DashPresentation::Dynamic { zero_point, .. } = self {
            *zero_point
        } else {
            DateTime::UNIX_EPOCH
        }
    }

    pub fn is_dynamic(&self) -> bool {
        matches!(self, DashPresentation::Dynamic { .. })
    }

    pub fn is_static(&self) -> bool {
        matches!(self, DashPresentation::Static)
    }
}

pub struct DashPeriod {
    /// The start of a period is specified either explicitly as an offset from the MPD timeline zero point
    /// (Period@start) or implicitly by the end of the previous period ([DASH] 5.3.2). The duration of a
    /// period is specified either explicitly with Period@duration or implicitly by the start point of the
    /// next period ([DASH] 5.3.2).
    /// See also § 8.1 First and last period timing in static presentations and § 8.2 First and last period
    /// timing in dynamic presentations.
    start_time: DateTime<Utc>,
    /// In a dynamic presentation, the last period MAY have a Period@duration, in which case it has a fixed
    /// duration. If without Period@duration, the last period in a dynamic presentation has an unlimited
    /// duration (that may later be shortened by an MPD update).
    duration: Option<Duration>,

    adaptation_sets: Vec<DashAdaptationSet>,
}

impl DashPeriod {
    pub fn from_mpd(
        base_url: &Url,
        period: Period,
        previous: Option<&mut Self>,
    ) -> IoriResult<Self> {
        // If start time is specified, then read it directly
        let (start_time, duration) = if let Some(start) = period.start {
            let start = DateTime::UNIX_EPOCH + TimeDelta::from_std(start)?;

            // if duration of last period is not specified, calculate by current period start and last period start
            if let Some(previous) = previous
                && previous.duration.is_none()
            {
                previous.duration = Some(start - previous.start_time);
            }

            (start, period.duration.map(TimeDelta::from_std).transpose()?)
        } else {
            // Otherwises, current.start = previous.start + previous.duration
            let start = previous
                .ok_or_else(|| {
                    IoriError::MpdParsing("Missing start time for initial period".to_string())
                })
                .and_then(|previous| {
                    previous
                        .duration
                        .map(|duration| previous.start_time + duration)
                        .ok_or_else(|| IoriError::MpdParsing("Missing period duration".to_string()))
                })?;

            (start, period.duration.map(TimeDelta::from_std).transpose()?)
        };

        let inherited = InheritedAddressingValues {
            segment_base: period.SegmentBase.as_ref(),
            segment_list: period.SegmentList.as_ref(),
            segment_template: period.SegmentTemplate.as_ref(),
        };

        let mut adaptation_sets = Vec::with_capacity(period.adaptations.len());
        for adaptation_set in period.adaptations {
            let period_base_url = period.BaseURL.first().map(|u| u.base.as_str());
            let base_url = match period_base_url {
                Some(period_base_url) => merge_baseurls(base_url, period_base_url)?,
                None => base_url.clone(),
            };
            let adaptation_set = DashAdaptationSet::from_mpd(base_url, &inherited, adaptation_set)?;
            adaptation_sets.push(adaptation_set);
        }

        Ok(Self {
            start_time,
            duration,
            adaptation_sets,
        })
    }
}

pub struct DashAdaptationSet {
    content_type: Option<DashAdaptationSetType>,

    representation: DashRepresentation,
}

impl DashAdaptationSet {
    pub fn from_mpd(
        base_url: Url,
        inherited: &InheritedAddressingValues,
        adaptation_set: AdaptationSet,
    ) -> IoriResult<Self> {
        let representation = adaptation_set
            .representations
            .into_iter()
            .max_by_key(best_representation)
            .ok_or_else(|| {
                IoriError::MpdParsing("No representations found in adaptation set".to_string())
            })?;

        let adaptation_set_base_url = adaptation_set.BaseURL.first().map(|u| u.base.as_str());
        let base_url = match adaptation_set_base_url {
            Some(adaptation_set_base_url) => merge_baseurls(&base_url, adaptation_set_base_url)?,
            None => base_url.clone(),
        };
        let representation = DashRepresentation::from_mpd(
            &base_url,
            InheritedAddressingValues {
                segment_base: adaptation_set.SegmentBase.as_ref(),
                segment_list: adaptation_set.SegmentList.as_ref(),
                segment_template: adaptation_set.SegmentTemplate.as_ref(),
            }
            .merge(inherited),
            adaptation_set.contentType.as_deref(),
            representation,
        )?;

        Ok(Self {
            content_type: adaptation_set
                .contentType
                .map(DashAdaptationSetType::from_string),
            representation,
        })
    }
}

/// Top-level type defined in [RFC6838](https://datatracker.ietf.org/doc/html/rfc6838#section-4.2)
pub enum DashAdaptationSetType {
    Text,
    Image,
    Audio,
    Video,
    Application,
    #[allow(unused)]
    Custom(String),
}

impl DashAdaptationSetType {
    fn to_segment_type(&self) -> SegmentType {
        match self {
            Self::Text => SegmentType::Subtitle,
            Self::Audio => SegmentType::Audio,
            Self::Video => SegmentType::Video,
            _ => SegmentType::Unknown,
        }
    }
}

impl DashAdaptationSetType {
    pub fn from_string(input: String) -> Self {
        match input.as_str() {
            "text" => Self::Text,
            "image" => Self::Image,
            "audio" => Self::Audio,
            "video" => Self::Video,
            "application" => Self::Application,
            _ => Self::Custom(input),
        }
    }
}

pub enum DashRepresentation {
    /// A representation that uses indexed addressing consists of a CMAF track file containing an
    /// index segment, an initialization segment and a sequence of media segments.
    ///
    /// > Note: This addressing mode is sometimes called "SegmentBase" in other documents.
    ///
    /// Not supported yet.
    #[allow(unused)]
    IndexedAddressing(SegmentBase),
    /// A representation that uses explicit addressing consists of a set of media segments accessed
    /// via URLs constructed using a template defined in the MPD, with the exact sample timeline time
    /// span covered by the samples in each media segment described in the MPD.
    ///
    /// > Note: This addressing mode is sometimes called "SegmentTemplate with SegmentTimeline" in other documents.
    ExplicitAddressing {
        initialization: Option<TemplateUrl>,
        media: TemplateUrl,
        start_number: u64,
        sample_timeline: SampleTimeline,
        availability_time_offset: TimeDelta,

        id: Option<String>,
        bandwidth: Option<u64>,
        mime_type: Option<String>,

        timeline_segments: Vec<TimelineSegment>,
    },
    /// A representation that uses simple addressing consists of a set of media segments accessed via
    /// URLs constructed using a template defined in the MPD, with the MPD describing the nominal time
    /// span of the sample timeline covered by each media segment.
    ///
    /// > Note: This addressing mode is sometimes called "SegmentTemplate without SegmentTimeline" in other documents.
    SimpleAddressing {
        initialization: Option<TemplateUrl>,
        media: TemplateUrl,
        start_number: u64,
        sample_timeline: SampleTimeline,
        duration: f64,
        availability_time_offset: TimeDelta,

        /// @eptDelta is expressed as an offset from the period start point to the segment start point
        /// of the first media segment ([DASH] 5.3.9.2). In other words, the value will be negative if
        /// the first media segment starts before the period start point.
        ept_delta: Option<i64>,

        id: Option<String>,
        bandwidth: Option<u64>,
        mime_type: Option<String>,
    },
    SegmentList {
        initialization: Option<SegmentListItem>,
        segment_items: Vec<SegmentListItem>,
        duration: u64,
        sample_timeline: SampleTimeline,

        mime_type: Option<String>,
    },
}

impl DashRepresentation {
    fn from_mpd(
        base_url: &Url,
        inherited: InheritedAddressingValues,
        content_type: Option<&str>,
        representation: Representation,
    ) -> IoriResult<Self> {
        let representation_base_url = representation.BaseURL.first().map(|u| u.base.as_str());
        let base_url = match representation_base_url {
            Some(adaptation_set_base_url) => merge_baseurls(base_url, adaptation_set_base_url)?,
            None => base_url.clone(),
        };

        let id = representation.id;
        let bandwidth = representation.bandwidth;
        let mime_type = representation
            .contentType
            .or_else(|| content_type.map(String::from));

        Ok(
            if let Some(segment_base) = representation
                .SegmentBase
                .as_ref()
                .or(inherited.segment_base)
            {
                // TODO: extract the needed data from segment_base
                Self::IndexedAddressing(segment_base.clone())
            } else if let Some(segment_list) = representation
                .SegmentList
                .as_ref()
                .or(inherited.segment_list)
            {
                let initialization = segment_list
                    .Initialization
                    .as_ref()
                    .and_then(|r| r.sourceURL.as_ref().map(|s| (s, r.range.as_deref())))
                    .map(|(url, range)| {
                        Ok::<SegmentListItem, IoriError>(SegmentListItem {
                            url: merge_baseurls(&base_url, url)?,
                            range: range.map(parse_media_range).transpose()?,
                        })
                    })
                    .transpose()?;

                let mut segment_items = Vec::with_capacity(segment_list.segment_urls.len());
                for segment_url in segment_list.segment_urls.iter() {
                    if let Some(media_url) = &segment_url.media {
                        let media_url = merge_baseurls(&base_url, media_url)?;
                        segment_items.push(SegmentListItem {
                            url: media_url,
                            range: segment_url
                                .mediaRange
                                .clone()
                                .map(parse_media_range)
                                .transpose()?,
                        });
                    } else {
                        segment_items.push(SegmentListItem {
                            url: base_url.clone(),
                            // TODO: support base_url range
                            range: None,
                        });
                    }
                }

                Self::SegmentList {
                    initialization,
                    segment_items,
                    duration: segment_list.duration.ok_or_else(|| {
                        IoriError::MpdParsing("Missing duration in SegmentList".to_string())
                    })?,
                    sample_timeline: SampleTimeline {
                        timescale: segment_list.timescale.unwrap_or(1),
                        presentation_time_offset: TimeDelta::zero(),
                    },
                    mime_type,
                }
            } else if let Some(template) = representation
                .SegmentTemplate
                .as_ref()
                .or(inherited.segment_template)
            {
                let initialization = template
                    .initialization
                    .as_ref()
                    .map(|new| merge_baseurls(&base_url, new))
                    .transpose()?
                    .map(|u| TemplateUrl(u.to_string()));
                let media = template
                    .media
                    .as_ref()
                    .map(|new| merge_baseurls(&base_url, new))
                    .transpose()?
                    .map(|u| TemplateUrl(u.to_string()))
                    .ok_or_else(|| {
                        IoriError::MpdParsing(
                            "Missing media url template in representation".to_string(),
                        )
                    })?;
                let start_number = template.startNumber.unwrap_or(1);
                let timescale = template.timescale.unwrap_or(1);
                let presentation_time_offset =
                    TimeDelta::from_secs(template.presentationTimeOffset.unwrap_or(0))?;
                let availability_time_offset =
                    TimeDelta::from_secs_f64(template.availabilityTimeOffset.unwrap_or_default())?;

                // ExplicitAddressing, aka SegmentTemplate with SegmentTimeline
                if let Some(ref timeline) = template.SegmentTimeline {
                    Self::ExplicitAddressing {
                        initialization,
                        media,
                        start_number,
                        sample_timeline: SampleTimeline {
                            timescale,
                            presentation_time_offset,
                        },
                        availability_time_offset,

                        id,
                        bandwidth,
                        mime_type,

                        timeline_segments: timeline
                            .segments
                            .iter()
                            .map(|r| TimelineSegment {
                                time: r.t,
                                duration: r.d,
                                repeat_count: r.r,
                            })
                            .collect(),
                    }
                } else {
                    // SimpleAddressing, aka SegmentTemplate without SegmentTimeline
                    Self::SimpleAddressing {
                        initialization,
                        media,
                        start_number,
                        sample_timeline: SampleTimeline {
                            timescale,
                            presentation_time_offset,
                        },
                        duration: template.duration.ok_or_else(|| {
                            IoriError::MpdParsing("Missing duration in SegmentTempalte".to_string())
                        })?,
                        availability_time_offset,
                        ept_delta: template.eptDelta,

                        id,
                        bandwidth,
                        mime_type,
                    }
                }
            } else {
                return Err(IoriError::MpdParsing(
                    "Invalid representation format".to_string(),
                ));
            },
        )
    }

    fn availability_time_offset(&self) -> TimeDelta {
        match self {
            Self::IndexedAddressing(_) => TimeDelta::zero(),
            Self::ExplicitAddressing {
                availability_time_offset,
                ..
            } => *availability_time_offset,
            Self::SimpleAddressing {
                availability_time_offset,
                ..
            } => *availability_time_offset,
            Self::SegmentList { .. } => TimeDelta::zero(),
        }
    }
}

pub struct TimelineSegment {
    pub time: Option<u64>,
    pub duration: u64,
    pub repeat_count: Option<i64>,
}

pub struct SegmentListItem {
    pub url: Url,
    pub range: Option<ByteRange>,
}

/// The samples within a representation exist on a linear sample timeline defined
/// by the encoder that creates the samples. Sample timelines are mapped onto the
/// MPD timeline by metadata stored in or referenced by the MPD ([DASH] 7.3.2).
///
/// The sample timeline does not determine what samples are presented. It merely
/// connects the timing of the representation to the MPD timeline and allows the
/// correct media segments to be identified when a DASH client makes scheduling
/// decisions driven by the MPD timeline. The exact connection between media segments
/// and the sample timeline is defined by the addressing mode.
///
/// The same sample timeline is shared by all representations in the same adaptation
/// set [DASH-CMAF]. Representations in different adaptation sets MAY use different
/// sample timelines.
///
/// A sample timeline is linear - encoders are expected to use an appropriate timescale
/// and sufficiently large timestamp fields to avoid any wrap-around. If wrap-around does
/// occur, a new period must be started in order to establish a new sample timeline.
pub struct SampleTimeline {
    /// A sample timeline is measured in timescale units defined as a number of units per second
    /// ([DASH] 5.3.9.2 and 5.3.9.6). This value (the timescale) SHALL be present in the MPD as
    /// SegmentTemplate@timescale or SegmentBase@timescale (depending on the addressing mode).
    timescale: u64,

    /// The zero point of a sample timeline may be at the start of the period or at any earlier
    /// point. The point on the sample timeline indicated by @presentationTimeOffset is equivalent
    /// to the period start point on the MPD timeline ([DASH] 5.3.9.2). The value is provided by
    /// SegmentTemplate@presentationTimeOffset or SegmentBase@presentationTimeOffset, depending on
    /// the addressing mode, and has a default value of 0 timescale units.
    presentation_time_offset: TimeDelta,
}

impl SampleTimeline {
    /// Map a time in timescale units to a time in presentation time.
    pub fn map_time(
        &self,
        period_start_time: DateTime<Utc>,
        segment_start_point: u64,
    ) -> IoriResult<DateTime<Utc>> {
        Ok(period_start_time - self.presentation_time_offset
            + TimeDelta::from_secs_f64(segment_start_point as f64 / self.timescale as f64)?)
    }
}

pub struct InheritedAddressingValues<'a> {
    segment_base: Option<&'a SegmentBase>,
    segment_list: Option<&'a SegmentList>,
    segment_template: Option<&'a SegmentTemplate>,
}

impl InheritedAddressingValues<'_> {
    pub fn merge(self, alternate: &Self) -> Self {
        InheritedAddressingValues {
            segment_base: self.segment_base.or(alternate.segment_base),
            segment_list: self.segment_list.or(alternate.segment_list),
            segment_template: self.segment_template.or(alternate.segment_template),
        }
    }
}

trait TimeDeltaExt {
    fn from_secs(u: u64) -> IoriResult<TimeDelta>;
    fn from_secs_f64(f: f64) -> IoriResult<TimeDelta>;
}

impl TimeDeltaExt for TimeDelta {
    fn from_secs(u: u64) -> IoriResult<TimeDelta> {
        Ok(TimeDelta::from_std(std::time::Duration::from_secs(u))?)
    }

    fn from_secs_f64(f: f64) -> IoriResult<TimeDelta> {
        Ok(TimeDelta::from_std(std::time::Duration::from_secs_f64(f))?)
    }
}
