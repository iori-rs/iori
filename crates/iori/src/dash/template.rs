// References:
// 1. https://github.com/clitic/vsd/blob/30ca1985e4a467ea3304b11c08d3176deaafd22a/vsd/src/dash/template.rs
// 2. https://github.com/emarsden/dash-mpd-rs/blob/6ebdfb4759adbda8233b5b3520804e23ff86e7de/src/fetch.rs#L435-L466

use regex::{Regex, Replacer};
use std::{collections::HashMap, sync::LazyLock};

// From https://dashif.org/docs/DASH-IF-IOP-v4.3.pdf:
// "For the avoidance of doubt, only %0[width]d is permitted and no other identifiers. The reason
// is that such a string replacement can be easily implemented without requiring a specific library."
//
// Instead of pulling in C printf() or a reimplementation such as the printf_compat crate, we reimplement
// this functionality directly.
//
// Example template: "$RepresentationID$/$Number%06d$.m4s"
static TEMPLATE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$(RepresentationID|Number|Bandwidth|Time|SubNumber)(?:%0([\d])d)?\$").unwrap()
});

pub struct Template<'a> {
    args: HashMap<&'a str, String>,
}

impl Template<'_> {
    /// This identifier is substituted with the value of the attribute
    /// **Representation**`@id` of the containing Representation
    pub const REPRESENTATION_ID: &'static str = "RepresentationID";

    /// This identifier is substituted with the number of the corresponding Segment,
    /// if _$SubNumber$_ is not present in the same string.
    ///
    /// If _$SubNumber$_ is present, this identifier is substituted with the number of
    /// the corresponding Segment sequence. For details, refer to subclauses 5.3.9.6.4 and 5.3.9.6.5.
    pub const NUMBER: &'static str = "Number";

    /// This identifier is substituted with the value of **Representation**`@bandwidth` attribute value.
    pub const BANDWIDTH: &'static str = "Bandwidth";

    /// This identifier is substituted with the value of the MPD start time of the Segment being accessed.
    /// For the Segment Timeline, this means that this identifier is substituted with the value of the
    /// **SegmentTimeline**`@t` attribute for the Segment being accessed. Either `$Number$` or `$Time$`
    /// may be used but not both at the same time.
    pub const TIME: &'static str = "Time";

    /// This identifier is substituted with the number of the corresponding Segment in a Seqment Sequence.
    /// This identifier shall only be present if either _$Number$_ or _$Time$_ are present as well.
    /// For details, refer to subclauses 5.3.9.6.4 and 5.3.9.6.5.
    ///
    /// Not implemented in iori yet.
    pub const SUB_NUMBER: &'static str = "SubNumber";

    pub fn new() -> Self {
        Self {
            args: HashMap::with_capacity(5),
        }
    }

    pub fn insert(&mut self, key: &'static str, value: String) -> &mut Self {
        self.args.insert(key, value);
        self
    }

    pub fn insert_optional(&mut self, key: &'static str, value: Option<String>) -> &mut Self {
        if let Some(value) = value {
            self.args.insert(key, value);
        }
        self
    }

    pub fn resolve(&self, template: &str) -> String {
        TEMPLATE_REGEX
            .replace_all(template, TemplateReplacer(&self.args))
            .to_string()
    }
}

impl Default for Template<'_> {
    fn default() -> Self {
        Self::new()
    }
}

struct TemplateReplacer<'a>(&'a HashMap<&'a str, String>);

impl Replacer for TemplateReplacer<'_> {
    fn replace_append(&mut self, caps: &regex::Captures<'_>, dst: &mut String) {
        let key = caps.get(1).unwrap().as_str();
        let Some(value) = self.0.get(key) else {
            dst.push_str(caps.get(0).unwrap().as_str());
            return;
        };

        let width = caps.get(2).map(|m| m.as_str().parse().unwrap());
        if let Some(width) = width {
            dst.push_str(&format!("{value:0>width$}", width = width));
        } else {
            dst.push_str(value.as_str());
        }
    }
}

pub struct TemplateUrl(pub String);

impl TemplateUrl {
    pub fn resolve(&self, template: &Template) -> String {
        template.resolve(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::dash::template::Template;

    #[test]
    fn test_template_replace() {
        let mut template = Template::new();
        template.insert("RepresentationID", "1".to_string());
        template.insert("Number", "2".to_string());
        template.insert("Time", "3".to_string());
        template.insert("Bandwidth", "4".to_string());

        // Single digit
        assert_eq!(template.resolve("$RepresentationID$"), "1".to_string());
        assert_eq!(template.resolve("$Number$"), "2".to_string());
        assert_eq!(template.resolve("$Time$"), "3".to_string());
        assert_eq!(template.resolve("$Bandwidth$"), "4".to_string());

        // Double digit
        assert_eq!(template.resolve("$RepresentationID%02d$"), "01".to_string());
        assert_eq!(template.resolve("$Number%02d$"), "02".to_string());
        assert_eq!(template.resolve("$Time%02d$"), "03".to_string());
        assert_eq!(template.resolve("$Bandwidth%02d$"), "04".to_string());

        // Mixed variables
        assert_eq!(
            template.resolve("$RepresentationID$-$Number$"),
            "1-2".to_string()
        );
        assert_eq!(template.resolve("$Time$-$Bandwidth$"), "3-4".to_string());

        // Mixed variables with width
        assert_eq!(
            template.resolve("$RepresentationID%02d$-$Number%09d$"),
            "01-000000002".to_string()
        );

        // All variables
        assert_eq!(
            template.resolve("$RepresentationID$-$Number$-$Time$-$Bandwidth$"),
            "1-2-3-4".to_string()
        );

        // All variables with different width
        assert_eq!(
            template.resolve("$RepresentationID%02d$-$Number%09d$-$Time%02d$-$Bandwidth%02d$"),
            "01-000000002-03-04".to_string()
        );

        // Unknown variable
        assert_eq!(template.resolve("$Unknown$"), "$Unknown$".to_string());
    }

    #[test]
    fn test_template_variable_not_defined() {
        let template = Template::new();
        assert_eq!(
            template.resolve("$RepresentationID$"),
            "$RepresentationID$".to_string()
        );
    }
}
