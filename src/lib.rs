pub mod errors;
pub mod query;
pub mod url;

use std::borrow::Cow;

use errors::Error;

static UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

pub type Result<T> = std::result::Result<T, Error>;

#[derive(PartialEq, Clone, Copy, Debug)]
enum Encoding {
    Path,
    PathSegment,
    Host,
    Zone,
    UserPassword,
    QueryComponent,
    Fragment,
}

pub fn query_unescape<'a>(s: &'a str) -> Result<Cow<'a, str>> {
    unescape(s, Encoding::QueryComponent)
}

pub fn path_unescape<'a>(s: &'a str) -> Result<Cow<'a, str>> {
    unescape(s, Encoding::PathSegment)
}

fn ishex(c: u8) -> bool {
    matches!(c as char, '0'..='9'|'a'..='f'|'A'..='F')
}

fn unhex(c: u8) -> u8 {
    match c as char {
        '0'..='9' => c - b'0',
        'a'..='f' => c - b'a' + 10,
        'A'..='F' => c - b'A' + 10,
        _ => 0,
    }
}

fn should_escape(c: u8, mode: Encoding) -> bool {
    let c = c as char;
    if matches!(c, 'a'..='z' | 'A' ..='Z' | '0'..='9') {
        return false;
    }

    if matches!(mode, Encoding::Host | Encoding::Zone)
        && matches!(
            c,
            '!' | '$'
                | '&'
                | '\''
                | '('
                | ')'
                | '*'
                | '+'
                | ','
                | ';'
                | '='
                | ':'
                | '['
                | ']'
                | '<'
                | '>'
                | '"'
        )
    {
        return false;
    }

    match c {
        '-' | '_' | '.' | '~' => return false,

        '$' | '&' | '+' | ',' | '/' | ':' | ';' | '=' | '?' | '@' => {
            // §2.2 Reserved characters (reserved)
            // Different sections of the URL allow a few of
            // the reserved characters to appear unescaped.
            match mode {
                Encoding::Path => {
                    // §3.3
                    // The RFC allows : @ & = + $ but saves / ; | for assigning
                    // meaning to individual path segments. This package
                    // only manipulates the path as a whole| so we allow those
                    // last three as well. That leaves only ? to escape.
                    return c == '?';
                }

                Encoding::PathSegment => {
                    // §3.3
                    // The RFC allows : @ & = + $ but saves / ; | for assigning
                    // meaning to individual path segments.
                    return c == '/' || c == ';' || c == ',' || c == '?';
                }

                Encoding::UserPassword => {
                    // §3.2.1
                    // The RFC allows ';'| ':'| '&'| '='| '+'| '$'| and '|' in
                    // userinfo| so we must escape only '@'| '/'| and '?'.
                    // The parsing of userinfo treats ':' as special so we must escape
                    // that too.
                    return c == '@' || c == '/' || c == '?' || c == ':';
                }

                Encoding::QueryComponent => {
                    // §3.4
                    // The RFC reserves (so we must escape) everything.
                    return true;
                }

                Encoding::Fragment => {
                    // §4.1
                    // The RFC text is silent but the grammar allows
                    // everything| so escape nothing.
                    return false;
                }
                _ => {}
            }
        }
        _ => {}
    }

    !(matches!(mode, Encoding::Fragment) && matches!(c, '!' | '(' | ')' | '*'))
}

fn unescape(s: &str, mode: Encoding) -> Result<Cow<'_, str>> {
    let mut n = 0;
    let mut has_plus = false;
    let bytes = s.as_bytes();
    let mut i = 0;
    loop {
        if i >= bytes.len() {
            break;
        }
        let c = bytes[i] as char;
        match c {
            '%' => {
                n += 1;
                if i + 2 >= s.len() || !ishex(bytes[i + 1]) || !ishex(bytes[i + 2]) {
                    let mut v = &bytes[i..];
                    if v.len() > 3 {
                        v = &v[..3];
                    }
                    return Err(Error::Parse(unsafe {
                        String::from_utf8_unchecked(v.to_vec())
                    }));
                }
                if mode == Encoding::Host
                    && unhex(bytes[i + 1]) < 8
                    && (&bytes[i..i + 3]).ne(b"%25")
                {
                    return Err(Error::Parse(unsafe {
                        String::from_utf8_unchecked((&bytes[i..i + 3]).to_vec())
                    }));
                }
                if mode == Encoding::Zone {
                    let v = unhex(bytes[i + 1]) << 4 | unhex(bytes[i + 2]);
                    if bytes[i..i + 3].ne(b"%25") && v != b' ' && should_escape(v, Encoding::Host) {
                        return Err(Error::Parse(unsafe {
                            String::from_utf8_unchecked((&bytes[i..i + 3]).to_vec())
                        }));
                    }
                }
                i += 3;
            }
            '+' => {
                has_plus = mode == Encoding::QueryComponent;
                i += 1;
            }
            _ => {
                if (mode == Encoding::Host || mode == Encoding::Zone)
                    && bytes[i] < 0x80
                    && should_escape(bytes[i], mode)
                {
                    return Err(Error::InvalidHost(unsafe {
                        String::from_utf8_unchecked((&bytes[i..i + 3]).to_vec())
                    }));
                }
                i += 1;
            }
        }
    }

    if n == 0 && !has_plus {
        return Ok(Cow::Borrowed(s));
    }
    Ok(Cow::Owned(build_unescape(s, n, mode)?))
}

fn build_unescape(input: &str, n: usize, mode: Encoding) -> Result<String> {
    let bytes = input.as_bytes();
    // let mut result = String::with_capacity(input.len() - 2 * n);
    let mut result = Vec::<u8>::with_capacity(input.len() - 2 * n);
    let mut i = 0;
    loop {
        if i >= bytes.len() {
            break;
        }
        match bytes[i] as char {
            '%' => {
                let a = (unhex(bytes[i + 1]) as u8) << 4;
                let b = (unhex(bytes[i + 2])) as u8;
                result.push(a | b);
                i += 2;
            }
            '+' => {
                let v = if mode == Encoding::QueryComponent {
                    ' '
                } else {
                    '+'
                };
                result.push(v as u8);
            }
            _ => {
                result.push(bytes[i]);
            }
        }
        i += 1;
    }

    Ok(unsafe { String::from_utf8_unchecked(result) })
}

pub fn path_escape(s: &str) -> Cow<'_, str> {
    escape(s, Encoding::PathSegment)
}

pub fn query_escape(s: &str) -> Cow<'_, str> {
    escape(s, Encoding::QueryComponent)
}

fn escape(s: &str, mode: Encoding) -> Cow<'_, str> {
    let (mut space_count, mut hex_count) = (0, 0);
    let bytes = s.as_bytes();
    for &c in bytes {
        if should_escape(c, mode) {
            if c == b' ' && mode == Encoding::QueryComponent {
                space_count += 1;
            } else {
                hex_count += 1;
            }
        }
    }

    if space_count == 0 && hex_count == 0 {
        return Cow::Borrowed(s);
    }

    if hex_count == 0 {
        return Cow::Owned(s.replace(' ', "+"));
    }

    let mut t = String::with_capacity(s.len() + 2 * hex_count);
    for &c in bytes {
        if c == b' ' && mode == Encoding::QueryComponent {
            t.push('+');
        } else if should_escape(c, mode) {
            t.push('%');
            t.push(UPPER_HEX[(c >> 4) as usize] as char);
            t.push(UPPER_HEX[(c & 0xf) as usize] as char);
        } else {
            t.push(c as char);
        }
    }
    Cow::Owned(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{should_escape, Encoding};

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4)
    }

    #[test]
    fn test_should_escape() {
        let tests = vec![
            // Unreserved characters (§2.3)
            ('a', Encoding::Path, false),
            ('a', Encoding::UserPassword, false),
            ('a', Encoding::QueryComponent, false),
            ('a', Encoding::Fragment, false),
            ('a', Encoding::Host, false),
            ('z', Encoding::Path, false),
            ('A', Encoding::Path, false),
            ('Z', Encoding::Path, false),
            ('0', Encoding::Path, false),
            ('9', Encoding::Path, false),
            ('-', Encoding::Path, false),
            ('-', Encoding::UserPassword, false),
            ('-', Encoding::QueryComponent, false),
            ('-', Encoding::Fragment, false),
            ('.', Encoding::Path, false),
            ('_', Encoding::Path, false),
            ('~', Encoding::Path, false),
            // User information (§3.2.1)
            (':', Encoding::UserPassword, true),
            ('/', Encoding::UserPassword, true),
            ('?', Encoding::UserPassword, true),
            ('@', Encoding::UserPassword, true),
            ('$', Encoding::UserPassword, false),
            ('&', Encoding::UserPassword, false),
            ('+', Encoding::UserPassword, false),
            (',', Encoding::UserPassword, false),
            (';', Encoding::UserPassword, false),
            ('=', Encoding::UserPassword, false),
            // Host (IP address, IPv6 address, registered name, port suffix; §3.2.2)
            ('!', Encoding::Host, false),
            ('$', Encoding::Host, false),
            ('&', Encoding::Host, false),
            ('\'', Encoding::Host, false),
            ('(', Encoding::Host, false),
            (')', Encoding::Host, false),
            ('*', Encoding::Host, false),
            ('+', Encoding::Host, false),
            (',', Encoding::Host, false),
            (';', Encoding::Host, false),
            ('=', Encoding::Host, false),
            (':', Encoding::Host, false),
            ('[', Encoding::Host, false),
            (']', Encoding::Host, false),
            ('0', Encoding::Host, false),
            ('9', Encoding::Host, false),
            ('A', Encoding::Host, false),
            ('z', Encoding::Host, false),
            ('_', Encoding::Host, false),
            ('-', Encoding::Host, false),
            ('.', Encoding::Host, false),
        ];

        for (input, mode, escape) in tests {
            let r = should_escape(input as u8, mode);
            if r != escape {
                println!(
                    "input: {}, mode: {:?}, expect: {}. actual: {}",
                    input, mode, escape, r
                );
            }
            assert_eq!(escape, r);
        }
    }

    #[test]
    fn test_unescape() {
        use std::borrow::Cow;

        let tests: Vec<(&str, Result<Cow<str>>)> = vec![
            ("", Ok(Cow::Owned("".to_string()))),
            ("abc", Ok(Cow::Owned("abc".to_string()))),
            ("1%41", Ok(Cow::Owned("1A".to_string()))),
            ("1%41%42%43", Ok(Cow::Owned("1ABC".to_string()))),
            ("%4a", Ok(Cow::Owned("J".to_string()))),
            ("%6F", Ok(Cow::Owned("o".to_string()))),
            (
                "%", // not enough characters after %
                Err(Error::Parse("%".to_string())),
            ),
            (
                "%a", // not enough characters after %
                Err(Error::Parse("%a".to_string())),
            ),
            (
                "%1", // not enough characters after %
                Err(Error::Parse("%1".to_string())),
            ),
            (
                "123%45%6", // not enough characters after %
                Err(Error::Parse("%6".to_string())),
            ),
            (
                "%zzzzz", // invalid hex digits
                Err(Error::Parse("%zz".to_string())),
            ),
            ("a+b", Ok(Cow::Owned("a b".to_string()))),
            ("a%20b", Ok(Cow::Owned("a b".to_string()))),
            ("%25", Ok(Cow::Owned("%".to_string()))),
        ];

        for (input, expect) in tests {
            let actual = query_unescape(input);
            assert_eq!(actual, expect);

            let mut in_value = input.to_string();
            let mut out_value = expect.clone();

            if input.contains('+') {
                in_value = input.replace('+', "%20");
                let result = path_unescape(&in_value);
                assert_eq!(expect, result);
                if expect.is_ok() {
                    if let Ok(s) = query_unescape(&input.replace('+', "XXX")) {
                        in_value = input.to_string();
                        let tmp = s.replace("XXX", "+");
                        out_value = Ok(Cow::Owned(tmp));
                    } else {
                        continue;
                    }
                }
            }

            let actual = path_unescape(&in_value);
            assert_eq!(actual, out_value);
        }
    }

    #[test]
    fn test_build_unescape() {
        let data: Vec<u8> = vec![
            104, 101, 108, 108, 111, 46, 37, 101, 52, 37, 98, 56, 37, 57, 54, 37, 101, 55, 37, 57,
            53, 37, 56, 99, 46, 99, 111, 109,
        ];
        let input = String::from_utf8_lossy(&data);
        let output = build_unescape(&input, 6, Encoding::Host).unwrap();
        let raw_世界 = vec![
            104, 101, 108, 108, 111, 46, 228, 184, 150, 231, 149, 140, 46, 99, 111, 109,
        ];
        let string_世界 = String::from_utf8_lossy(&raw_世界);
        println!("{}", string_世界);
        // assert_eq!(s, a);
        assert_eq!(string_世界.as_bytes(), output.as_bytes());
    }

    #[test]
    fn test_query_escape() {
        let tests = vec![
            ("", ""),
            ("abc", "abc"),
            ("one two", "one+two"),
            ("10%", "10%25"),
            (
                " ?&=#+%!<>#\"{}|\\^[]`☺\t:/@$'()*,;",
                "+%3F%26%3D%23%2B%25%21%3C%3E%23%22%7B%7D%7C%5C%5E%5B%5D%60%E2%98%BA%09%3A%2F%40%24%27%28%29%2A%2C%3B",
            ),
        ];

        for (input, output) in tests {
            let actual = query_escape(input).to_string();
            assert_eq!(output.to_string(), actual);

            let roundtrip = query_unescape(&actual);
            assert_eq!(roundtrip, Ok(Cow::Borrowed(input)));
        }
    }

    #[test]
    fn test_path_escape() {
        let tests = vec![
            ("", ""),
            ("abc", "abc"),
            ("abc+def", "abc+def"),
            ("a/b", "a%2Fb"),
            ("one two", "one%20two"),
            ("10%", "10%25"),
            (
                " ?&=#+%!<>#\"{}|\\^[]`☺\t:/@$'()*,;",
                "%20%3F&=%23+%25%21%3C%3E%23%22%7B%7D%7C%5C%5E%5B%5D%60%E2%98%BA%09:%2F@$%27%28%29%2A%2C%3B",
            ),
        ];

        for (input, output) in tests {
            let actual = path_escape(input).to_string();
            assert_eq!(output.to_string(), actual);

            let roundtrip = path_unescape(&actual);
            assert_eq!(roundtrip, Ok(Cow::Borrowed(input)));
        }
    }
}
