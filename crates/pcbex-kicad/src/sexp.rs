//! Bounded, iterative KiCad S-expression parsing.
//!
//! The parser deliberately keeps the lexical and structural limits in one
//! place.  KiCad files are untrusted input when they are processed by the
//! headless pipeline, so all limits are checked before allocating or pushing
//! another item.

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Sexp {
    Atom(String),
    QuotedAtom(String),
    List(Vec<Sexp>),
}

impl Sexp {
    pub(crate) fn as_list(&self) -> Option<&[Sexp]> {
        match self {
            Self::List(values) => Some(values),
            Self::Atom(_) | Self::QuotedAtom(_) => None,
        }
    }
}

/// Maximum source size accepted by the production parser (128 MiB).
pub(crate) const MAX_SEXP_INPUT_BYTES: usize = 128 * 1024 * 1024;
/// Maximum number of lexical tokens, including opening and closing parens.
pub(crate) const MAX_SEXP_TOKENS: usize = 4_000_000;
/// Maximum decoded byte length of one atom.
pub(crate) const MAX_SEXP_ATOM_BYTES: usize = 4 * 1024 * 1024;
/// Maximum number of simultaneously open lists.
pub(crate) const MAX_SEXP_NESTING_DEPTH: usize = 128;
/// Maximum direct children in one list or in a top-level sequence.
pub(crate) const MAX_SEXP_DIRECT_ELEMENTS: usize = 1_000_000;
/// Maximum number of spans returned by [`list_spans`].
pub(crate) const MAX_SEXP_SPANS: usize = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SexpLimits {
    pub(crate) input_bytes: usize,
    pub(crate) tokens: usize,
    pub(crate) atom_bytes: usize,
    pub(crate) nesting_depth: usize,
    pub(crate) direct_elements: usize,
    pub(crate) spans: usize,
}

impl Default for SexpLimits {
    fn default() -> Self {
        Self {
            input_bytes: MAX_SEXP_INPUT_BYTES,
            tokens: MAX_SEXP_TOKENS,
            atom_bytes: MAX_SEXP_ATOM_BYTES,
            nesting_depth: MAX_SEXP_NESTING_DEPTH,
            direct_elements: MAX_SEXP_DIRECT_ELEMENTS,
            spans: MAX_SEXP_SPANS,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Token<'a> {
    Open,
    Close,
    Atom(&'a str),
    QuotedAtom(String),
}

struct Lexer<'a> {
    source: &'a str,
    position: usize,
    token_count: usize,
    limits: SexpLimits,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str, limits: SexpLimits) -> Result<Self, String> {
        if source.len() > limits.input_bytes {
            return Err("KiCad s-expression input exceeds configured byte limit".to_string());
        }
        Ok(Self {
            source,
            position: 0,
            token_count: 0,
            limits,
        })
    }

    fn next_token(&mut self) -> Result<Option<Token<'a>>, String> {
        self.skip_whitespace();
        if self.position == self.source.len() {
            return Ok(None);
        }
        if self.token_count >= self.limits.tokens {
            return Err("KiCad s-expression token count exceeds configured limit".to_string());
        }
        let start = self.position;
        let character = self.char_at(self.position).ok_or_else(|| {
            // `source` is a `str`, so this can only indicate an internal
            // cursor bug.  Keep the user-visible error stable and generic.
            "invalid KiCad s-expression cursor".to_string()
        })?;
        let token = match character {
            '(' => {
                self.position += 1;
                Token::Open
            }
            ')' => {
                self.position += 1;
                Token::Close
            }
            '"' => Token::QuotedAtom(self.quoted_atom()?),
            _ => {
                self.position += character.len_utf8();
                while self.position < self.source.len() {
                    let character = self
                        .char_at(self.position)
                        .ok_or_else(|| "invalid KiCad s-expression cursor".to_string())?;
                    if character.is_whitespace() || matches!(character, '(' | ')') {
                        break;
                    }
                    self.position += character.len_utf8();
                }
                let atom = self
                    .source
                    .get(start..self.position)
                    .ok_or_else(|| "invalid KiCad s-expression atom boundary".to_string())?;
                if atom.len() > self.limits.atom_bytes {
                    return Err("KiCad s-expression atom exceeds configured byte limit".to_string());
                }
                Token::Atom(atom)
            }
        };
        self.bump_token_count()?;
        Ok(Some(token))
    }

    fn quoted_atom(&mut self) -> Result<String, String> {
        // Consume the opening quote.  `next_token` only calls this when the
        // cursor is at a valid quote.
        self.position += 1;
        let mut value = String::new();
        while self.position < self.source.len() {
            let character = self
                .char_at(self.position)
                .ok_or_else(|| "invalid KiCad s-expression cursor".to_string())?;
            self.position += character.len_utf8();
            match character {
                '"' => return Ok(value),
                '\\' => {
                    let escaped = self
                        .char_at(self.position)
                        .ok_or_else(|| "unterminated KiCad s-expression escape".to_string())?;
                    self.position += escaped.len_utf8();
                    self.push_decoded(&mut value, escaped)?;
                }
                other => self.push_decoded(&mut value, other)?,
            }
        }
        Err("unterminated KiCad s-expression string".to_string())
    }

    fn push_decoded(&self, value: &mut String, character: char) -> Result<(), String> {
        let additional = character.len_utf8();
        let Some(next_length) = value.len().checked_add(additional) else {
            return Err("KiCad s-expression atom exceeds configured byte limit".to_string());
        };
        if next_length > self.limits.atom_bytes {
            return Err("KiCad s-expression atom exceeds configured byte limit".to_string());
        }
        value.try_reserve(additional).map_err(|_| {
            "unable to allocate KiCad s-expression atom within configured limit".to_string()
        })?;
        value.push(character);
        Ok(())
    }

    fn bump_token_count(&mut self) -> Result<(), String> {
        if self.token_count >= self.limits.tokens {
            return Err("KiCad s-expression token count exceeds configured limit".to_string());
        }
        self.token_count += 1;
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while self.position < self.source.len() {
            let Some(character) = self.char_at(self.position) else {
                break;
            };
            if !character.is_whitespace() {
                break;
            }
            self.position += character.len_utf8();
        }
    }

    fn has_non_whitespace(&self) -> bool {
        let mut position = self.position;
        while position < self.source.len() {
            let Some(character) = self.char_at(position) else {
                return false;
            };
            if !character.is_whitespace() {
                return true;
            }
            position += character.len_utf8();
        }
        false
    }

    fn next_is_value(&self) -> bool {
        let mut position = self.position;
        while position < self.source.len() {
            let Some(character) = self.char_at(position) else {
                return false;
            };
            if !character.is_whitespace() {
                return character != ')';
            }
            position += character.len_utf8();
        }
        false
    }

    fn char_at(&self, position: usize) -> Option<char> {
        self.source.get(position..)?.chars().next()
    }
}

struct ListFrame {
    values: Vec<Sexp>,
    direct_elements: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootMode {
    Sequence,
    Document,
}

fn reserve<T>(values: &mut Vec<T>, additional: usize, what: &'static str) -> Result<(), String> {
    values
        .try_reserve(additional)
        .map_err(|_| format!("unable to allocate KiCad s-expression {what}"))
}

fn add_direct_element(
    count: &mut usize,
    limit: usize,
    values: &mut Vec<Sexp>,
    value: Sexp,
) -> Result<(), String> {
    if *count >= limit {
        return Err("KiCad s-expression direct element count exceeds configured limit".to_string());
    }
    reserve(values, 1, "list elements")?;
    values.push(value);
    *count += 1;
    Ok(())
}

fn owned_atom(atom: &str) -> Result<String, String> {
    let mut value = String::new();
    value.try_reserve_exact(atom.len()).map_err(|_| {
        "unable to allocate KiCad s-expression atom within configured limit".to_string()
    })?;
    value.push_str(atom);
    Ok(value)
}

fn parse_with_limits(
    source: &str,
    limits: SexpLimits,
    root_mode: RootMode,
) -> Result<Vec<Sexp>, String> {
    let mut lexer = Lexer::new(source, limits)?;
    let mut roots = Vec::new();
    let mut root_count = 0usize;
    let mut stack: Vec<ListFrame> = Vec::new();
    reserve(&mut roots, 0, "top-level elements")?;

    loop {
        if root_mode == RootMode::Document
            && stack.is_empty()
            && root_count != 0
            && lexer.has_non_whitespace()
        {
            return Err("trailing tokens in KiCad document".to_string());
        }
        if lexer.next_is_value() {
            let direct_count = stack
                .last()
                .map_or(root_count, |frame| frame.direct_elements);
            if direct_count >= limits.direct_elements {
                return Err(
                    "KiCad s-expression direct element count exceeds configured limit".to_string(),
                );
            }
        }
        let Some(token) = lexer.next_token()? else {
            break;
        };
        match token {
            Token::Open => {
                if stack.is_empty() && root_mode == RootMode::Document && root_count != 0 {
                    return Err("trailing tokens in KiCad document".to_string());
                }
                if stack.len() >= limits.nesting_depth {
                    return Err(
                        "KiCad s-expression nesting depth exceeds configured limit".to_string()
                    );
                }
                if let Some(parent) = stack.last_mut() {
                    if parent.direct_elements >= limits.direct_elements {
                        return Err(
                            "KiCad s-expression direct element count exceeds configured limit"
                                .to_string(),
                        );
                    }
                    parent.direct_elements += 1;
                } else if root_count >= limits.direct_elements {
                    return Err(
                        "KiCad s-expression top-level element count exceeds configured limit"
                            .to_string(),
                    );
                } else {
                    root_count += 1;
                }
                reserve(&mut stack, 1, "list stack")?;
                stack.push(ListFrame {
                    values: Vec::new(),
                    direct_elements: 0,
                });
            }
            Token::Close => {
                let Some(frame) = stack.pop() else {
                    if root_mode == RootMode::Document && root_count != 0 {
                        return Err("trailing tokens in KiCad document".to_string());
                    }
                    return Err("unexpected ')'".to_string());
                };
                let list = Sexp::List(frame.values);
                if let Some(parent) = stack.last_mut() {
                    reserve(&mut parent.values, 1, "list elements")?;
                    parent.values.push(list);
                } else {
                    reserve(&mut roots, 1, "top-level elements")?;
                    roots.push(list);
                }
            }
            Token::Atom(atom) => {
                if stack.is_empty() && root_mode == RootMode::Document && root_count != 0 {
                    return Err("trailing tokens in KiCad document".to_string());
                }
                let value = Sexp::Atom(owned_atom(atom)?);
                if let Some(frame) = stack.last_mut() {
                    add_direct_element(
                        &mut frame.direct_elements,
                        limits.direct_elements,
                        &mut frame.values,
                        value,
                    )?;
                } else {
                    add_direct_element(&mut root_count, limits.direct_elements, &mut roots, value)?;
                }
            }
            Token::QuotedAtom(atom) => {
                if stack.is_empty() && root_mode == RootMode::Document && root_count != 0 {
                    return Err("trailing tokens in KiCad document".to_string());
                }
                let value = Sexp::QuotedAtom(atom);
                if let Some(frame) = stack.last_mut() {
                    add_direct_element(
                        &mut frame.direct_elements,
                        limits.direct_elements,
                        &mut frame.values,
                        value,
                    )?;
                } else {
                    add_direct_element(&mut root_count, limits.direct_elements, &mut roots, value)?;
                }
            }
        }
    }
    if !stack.is_empty() {
        return Err("unexpected end of document".to_string());
    }
    Ok(roots)
}

fn parse_sequence_with_limits(source: &str, limits: SexpLimits) -> Result<Vec<Sexp>, String> {
    parse_with_limits(source, limits, RootMode::Sequence)
}

pub(crate) fn parse_sequence(source: &str) -> Result<Vec<Sexp>, String> {
    parse_sequence_with_limits(source, SexpLimits::default())
}

pub(crate) fn parse_document(source: &str) -> Result<Sexp, String> {
    let mut roots = parse_with_limits(source, SexpLimits::default(), RootMode::Document)?;
    match roots.len() {
        0 => Err("unexpected end of document".to_string()),
        1 => Ok(roots.pop().expect("one root was checked")),
        _ => Err("trailing tokens in KiCad document".to_string()),
    }
}

fn scan_list_spans_with_limits(
    source: &str,
    name: &str,
    target_depth: usize,
    limits: SexpLimits,
) -> Result<Vec<(usize, usize)>, String> {
    if source.len() > limits.input_bytes {
        return Err("KiCad s-expression input exceeds configured byte limit".to_string());
    }
    if target_depth > limits.nesting_depth {
        return Err("KiCad s-expression nesting depth exceeds configured limit".to_string());
    }
    let mut depth = 0usize;
    let mut stack: Vec<(usize, usize, bool)> = Vec::new();
    let mut spans = Vec::new();
    let mut index = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut token_start = true;
    while index < source.len() {
        let character = source
            .get(index..)
            .and_then(|remaining| remaining.chars().next())
            .ok_or_else(|| "invalid KiCad s-expression cursor".to_string())?;
        if quoted {
            if escaped {
                escaped = false;
                index += character.len_utf8();
            } else if character == '\\' {
                escaped = true;
                index += character.len_utf8();
            } else if character == '"' {
                quoted = false;
                token_start = true;
                index += character.len_utf8();
            } else {
                index += character.len_utf8();
            }
            continue;
        }
        match character {
            '"' if token_start => {
                quoted = true;
                token_start = false;
                index += character.len_utf8();
            }
            '(' => {
                if depth >= limits.nesting_depth {
                    return Err(
                        "KiCad s-expression nesting depth exceeds configured limit".to_string()
                    );
                }
                depth += 1;
                let matches = list_head_matches(source, index, name)?;
                stack
                    .try_reserve(1)
                    .map_err(|_| "unable to allocate KiCad s-expression span stack".to_string())?;
                stack.push((index, depth, matches));
                token_start = true;
                index += character.len_utf8();
            }
            ')' => {
                let Some((start, list_depth, matches)) = stack.pop() else {
                    return Err("unbalanced KiCad document".to_string());
                };
                if matches && list_depth == target_depth {
                    if spans.len() >= limits.spans {
                        return Err(
                            "KiCad s-expression span count exceeds configured limit".to_string()
                        );
                    }
                    spans
                        .try_reserve(1)
                        .map_err(|_| "unable to allocate KiCad s-expression spans".to_string())?;
                    spans.push((start, index + 1));
                }
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| "unbalanced KiCad document".to_string())?;
                token_start = true;
                index += character.len_utf8();
            }
            character if character.is_whitespace() => {
                token_start = true;
                index += character.len_utf8();
            }
            _ => {
                token_start = false;
                index += character.len_utf8();
            }
        }
    }
    if quoted || escaped || depth != 0 {
        return Err("unterminated KiCad document".to_string());
    }
    Ok(spans)
}

pub(crate) fn list_spans(
    source: &str,
    name: &str,
    target_depth: usize,
) -> Result<Vec<(usize, usize)>, String> {
    scan_list_spans_with_limits(source, name, target_depth, SexpLimits::default())
}

fn list_head_matches(source: &str, open: usize, name: &str) -> Result<bool, String> {
    let mut position = open + 1;
    while position < source.len() {
        let character = source
            .get(position..)
            .and_then(|remaining| remaining.chars().next())
            .ok_or_else(|| "invalid KiCad s-expression cursor".to_string())?;
        if !character.is_whitespace() {
            break;
        }
        position += character.len_utf8();
    }
    let Some(first) = source
        .get(position..)
        .and_then(|remaining| remaining.chars().next())
    else {
        return Ok(name.is_empty());
    };
    if first != '"' {
        let atom_start = position;
        while position < source.len() {
            let character = source
                .get(position..)
                .and_then(|remaining| remaining.chars().next())
                .ok_or_else(|| "invalid KiCad s-expression cursor".to_string())?;
            if character.is_whitespace() || matches!(character, '(' | ')') {
                break;
            }
            position += character.len_utf8();
        }
        return Ok(source.get(atom_start..position) == Some(name));
    }

    position += first.len_utf8();
    let mut name_characters = name.chars();
    while position < source.len() {
        let character = source
            .get(position..)
            .and_then(|remaining| remaining.chars().next())
            .ok_or_else(|| "invalid KiCad s-expression cursor".to_string())?;
        position += character.len_utf8();
        let decoded = if character == '\\' {
            let Some(escaped) = source
                .get(position..)
                .and_then(|remaining| remaining.chars().next())
            else {
                return Ok(false);
            };
            position += escaped.len_utf8();
            escaped
        } else if character == '"' {
            return Ok(name_characters.next().is_none());
        } else {
            character
        };
        if name_characters.next() != Some(decoded) {
            return Ok(false);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> SexpLimits {
        SexpLimits {
            input_bytes: 64,
            tokens: 8,
            atom_bytes: 8,
            nesting_depth: 3,
            direct_elements: 3,
            spans: 2,
        }
    }

    #[test]
    fn quoted_atoms_are_not_parentheses() {
        let roots =
            parse_sequence_with_limits(r#"("(" ")" "" "日本語" "\\\"")"#, SexpLimits::default())
                .unwrap();
        assert_eq!(
            roots,
            vec![Sexp::List(vec![
                Sexp::QuotedAtom("(".into()),
                Sexp::QuotedAtom(")".into()),
                Sexp::QuotedAtom(String::new()),
                Sexp::QuotedAtom("日本語".into()),
                Sexp::QuotedAtom("\\\"".into()),
            ])]
        );
        let escaped =
            parse_sequence_with_limits(r#"("a\"b" "c\\d")"#, SexpLimits::default()).unwrap();
        assert_eq!(
            escaped,
            vec![Sexp::List(vec![
                Sexp::QuotedAtom("a\"b".into()),
                Sexp::QuotedAtom("c\\d".into()),
            ])]
        );
    }

    #[test]
    fn sequence_accepts_empty_and_multiple_roots() {
        assert!(parse_sequence("").unwrap().is_empty());
        assert_eq!(parse_sequence("a (b)").unwrap().len(), 2);
        assert_eq!(parse_document("a").unwrap(), Sexp::Atom("a".into()));
        assert_eq!(
            parse_document("a b").unwrap_err(),
            "trailing tokens in KiCad document"
        );
    }

    #[test]
    fn tiny_limits_reject_exactly_on_the_next_item() {
        let cases = [
            (
                "input",
                "123456789",
                SexpLimits {
                    input_bytes: 8,
                    ..limits()
                },
            ),
            (
                "tokens",
                "a b c d",
                SexpLimits {
                    tokens: 3,
                    ..limits()
                },
            ),
            (
                "atom",
                "123456789",
                SexpLimits {
                    atom_bytes: 8,
                    ..limits()
                },
            ),
            (
                "depth",
                "(((a)))",
                SexpLimits {
                    nesting_depth: 2,
                    ..limits()
                },
            ),
            (
                "elements",
                "(a b c d)",
                SexpLimits {
                    direct_elements: 3,
                    ..limits()
                },
            ),
        ];
        for (label, source, custom) in cases {
            let result = parse_sequence_with_limits(source, custom);
            assert!(result.is_err(), "{label} must reject +1");
        }
        assert!(
            parse_sequence_with_limits(
                "(a b c)",
                SexpLimits {
                    direct_elements: 3,
                    ..limits()
                }
            )
            .is_ok()
        );
        assert!(
            parse_sequence_with_limits(
                "a b c",
                SexpLimits {
                    direct_elements: 3,
                    ..limits()
                }
            )
            .is_ok()
        );
        assert!(
            parse_sequence_with_limits(
                "(a)",
                SexpLimits {
                    tokens: 3,
                    ..limits()
                }
            )
            .is_ok()
        );
        assert!(
            parse_sequence_with_limits(
                "(a)",
                SexpLimits {
                    tokens: 2,
                    ..limits()
                }
            )
            .is_err()
        );
        assert!(
            parse_sequence_with_limits(
                "12345678",
                SexpLimits {
                    input_bytes: 8,
                    ..limits()
                }
            )
            .is_ok()
        );
        assert!(
            parse_sequence_with_limits(
                "😀",
                SexpLimits {
                    input_bytes: 4,
                    ..limits()
                }
            )
            .is_ok()
        );
        assert!(
            parse_sequence_with_limits(
                "😀",
                SexpLimits {
                    input_bytes: 3,
                    ..limits()
                }
            )
            .is_err()
        );
        assert!(
            parse_sequence_with_limits(
                "a b c",
                SexpLimits {
                    tokens: 3,
                    ..limits()
                }
            )
            .is_ok()
        );
        assert!(
            parse_sequence_with_limits(
                "12345678",
                SexpLimits {
                    atom_bytes: 8,
                    ..limits()
                }
            )
            .is_ok()
        );
        assert!(
            parse_sequence_with_limits(
                "((a))",
                SexpLimits {
                    nesting_depth: 2,
                    ..limits()
                }
            )
            .is_ok()
        );
        let quoted_unicode = SexpLimits {
            atom_bytes: 4,
            ..SexpLimits::default()
        };
        assert!(parse_sequence_with_limits("\"😀\"", quoted_unicode).is_ok());
        assert!(
            parse_sequence_with_limits(
                "\"😀\"",
                SexpLimits {
                    atom_bytes: 3,
                    ..quoted_unicode
                }
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_input_is_bounded_and_non_recursive() {
        assert_eq!(parse_sequence(")").unwrap_err(), "unexpected ')'");
        assert_eq!(
            parse_sequence("(").unwrap_err(),
            "unexpected end of document"
        );
        let deep = "(".repeat(MAX_SEXP_NESTING_DEPTH + 1);
        assert!(parse_sequence(&deep).is_err());
        assert_eq!(
            parse_sequence("\"unterminated").unwrap_err(),
            "unterminated KiCad s-expression string"
        );
        assert_eq!(
            parse_sequence("\"dangling\\").unwrap_err(),
            "unterminated KiCad s-expression escape"
        );
    }

    #[test]
    fn document_mode_rejects_a_second_root_before_materializing_it() {
        let custom = SexpLimits {
            direct_elements: 1_000_000,
            ..SexpLimits::default()
        };
        assert_eq!(
            parse_with_limits("(a) b", custom, RootMode::Document).unwrap_err(),
            "trailing tokens in KiCad document"
        );
        assert_eq!(
            parse_with_limits("(a) (b)", custom, RootMode::Document).unwrap_err(),
            "trailing tokens in KiCad document"
        );
        assert_eq!(
            parse_with_limits("a \"unterminated", custom, RootMode::Document).unwrap_err(),
            "trailing tokens in KiCad document"
        );
        assert_eq!(
            parse_with_limits("(a)", custom, RootMode::Document).unwrap(),
            vec![Sexp::List(vec![Sexp::Atom("a".into())])]
        );
    }

    #[test]
    fn full_direct_element_limit_rejects_before_lexing_the_next_atom() {
        let limited = SexpLimits {
            direct_elements: 1,
            ..SexpLimits::default()
        };
        assert_eq!(
            parse_sequence_with_limits(r#"(a "unterminated)"#, limited).unwrap_err(),
            "KiCad s-expression direct element count exceeds configured limit"
        );
        assert_eq!(
            parse_sequence_with_limits(r#"a "unterminated"#, limited).unwrap_err(),
            "KiCad s-expression direct element count exceeds configured limit"
        );
    }

    #[test]
    fn spans_honor_quotes_depth_and_count() {
        let source = r#"(root (item "(not-a-list)") (item x) (item y))"#;
        assert_eq!(list_spans(source, "item", 2).unwrap().len(), 3);
        let limited = SexpLimits {
            spans: 2,
            ..SexpLimits::default()
        };
        assert!(scan_list_spans_with_limits(source, "item", 2, limited).is_err());
        let exact = SexpLimits {
            spans: 2,
            ..SexpLimits::default()
        };
        assert!(scan_list_spans_with_limits("(root (item x) (item y))", "item", 2, exact).is_ok());
        assert!(
            scan_list_spans_with_limits(
                "(x)",
                "x",
                1,
                SexpLimits {
                    input_bytes: 3,
                    ..SexpLimits::default()
                }
            )
            .is_ok()
        );
        assert!(
            scan_list_spans_with_limits(
                "(x) ",
                "x",
                1,
                SexpLimits {
                    input_bytes: 3,
                    ..SexpLimits::default()
                }
            )
            .is_err()
        );
        assert!(
            scan_list_spans_with_limits(
                "((x))",
                "x",
                2,
                SexpLimits {
                    nesting_depth: 2,
                    ..SexpLimits::default()
                }
            )
            .is_ok()
        );
        assert!(
            scan_list_spans_with_limits(
                "((x))",
                "x",
                2,
                SexpLimits {
                    nesting_depth: 1,
                    ..SexpLimits::default()
                }
            )
            .is_err()
        );
        assert_eq!(
            list_spans("(root\u{00a0}(item\u{00a0}x))", "item", 2).unwrap(),
            vec![(7, 16)]
        );
        assert_eq!(
            list_spans(r#"(root foo"bar (item x))"#, "item", 2).unwrap(),
            vec![(14, 22)]
        );
        let quoted_head = r#"(root ("item" x))"#;
        let quoted_spans = list_spans(quoted_head, "item", 2).unwrap();
        assert_eq!(quoted_spans.len(), 1);
        assert_eq!(
            &quoted_head[quoted_spans[0].0..quoted_spans[0].1],
            "(\"item\" x)"
        );
    }
}
