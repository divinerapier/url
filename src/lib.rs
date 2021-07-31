pub mod errors;
pub mod url;

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

pub fn query_unescape(s: &str) -> Result<String> {
    unescape(s, Encoding::QueryComponent)
}

pub fn path_unescape(s: &str) -> Result<String> {
    unescape(s, Encoding::PathSegment)
}

fn ishex(c: u8) -> bool {
    matches!(c as char, '0'..='9'|'a'..='f'|'A'..='F')
}

fn unhex(c: u8) -> u8 {
    match c as char {
        '0'..='9' => c - '0' as u8,
        'a'..='f' => c - 'a' as u8 + 10,
        'A'..='F' => c - 'A' as u8 + 10,
        _ => 0,
    }
}

fn should_escape(c: u8, mode: Encoding) -> bool {
    let c = c as char;
    if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' {
        return false;
    }

    match mode {
        Encoding::Host | Encoding::Zone => match c {
            '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=' | ':' | '[' | ']'
            | '<' | '>' | '"' => return false,
            _ => {}
        },
        _ => {}
    };

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

    if mode == Encoding::Fragment {
        match c {
            '!' | '(' | ')' | '*' => return false,
            _ => {}
        }
    }

    true
}

fn unescape(s: &str, mode: Encoding) -> Result<String> {
    println!("input: {}, length: {}", s, s.len());
    for tt in s.as_bytes() {
        print!("{}, ", *tt as u32);
    }
    println!();
    for tt in s.chars() {
        print!("{}, ", tt as u32);
    }
    println!();
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
                    println!("parse error. 1. {:?}", v);
                    return Err(Error::Parse(unsafe {
                        String::from_utf8_unchecked(v.to_vec())
                    }));
                }
                if mode == Encoding::Host
                    && unhex(bytes[i + 1]) < 8
                    && (&bytes[i..i + 3]).ne(b"%25")
                {
                    println!("parse error. 2. {:?}", &bytes[i..i + 3]);
                    return Err(Error::Parse(unsafe {
                        String::from_utf8_unchecked((&bytes[i..i + 3]).to_vec())
                    }));
                }
                if mode == Encoding::Zone {
                    let v = unhex(bytes[i + 1]) << 4 | unhex(bytes[i + 2]);
                    if bytes[i..i + 3].ne(b"%25") && v != b' ' && should_escape(v, Encoding::Host) {
                        println!("parse error. 3. {:?}", v);
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
        return Ok(s.to_string());
    }
    println!("s: {:?}", s);
    println!("n: {:?}", n);
    println!("mode: {:?}", mode);
    build_unescape(s, n, mode)
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
                println!("1. {}. write: {}", i, (a | b) as char as u32);
                result.push(a | b);
                i += 2;
            }
            '+' => {
                let v = if mode == Encoding::QueryComponent {
                    ' '
                } else {
                    '+'
                };
                println!("2. {}. write: {}", i, v as u32);
                result.push(v as u8);
            }
            _ => {
                println!("3. {}. write: {}", i, bytes[i] as u32);
                result.push(bytes[i]);
            }
        }
        i += 1;
    }
    // println!("dump:");
    // for c in result.chars() {
    //     print!("{}, ", c as u32)
    // }
    // println!();
    // for c in result.chars() {
    //     print!("{}, ", c as u32);
    // }
    // println!("\ndump finish");
    // println!("result: {}", result);
    // let finally = String::from_utf8_lossy(result.as_bytes()).to_string();
    // println!("finally: {}", finally);
    // Ok(finally)
    {
        println!("bs");
        for v in result.iter() {
            print!("{}, ", *v);
        }
        println!();
    }
    Ok(unsafe { String::from_utf8_unchecked(result) })
}

fn escape(s: &str, mode: Encoding) -> String {
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
        return s.to_string();
    }

    if hex_count == 0 {
        return s.replace(' ', "+");
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
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::result;

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
        let tests: Vec<(&str, Result<String>)> = vec![
            ("", Ok("".to_string())),
            ("abc", Ok("abc".to_string())),
            ("1%41", Ok("1A".to_string())),
            ("1%41%42%43", Ok("1ABC".to_string())),
            ("%4a", Ok("J".to_string())),
            ("%6F", Ok("o".to_string())),
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
            ("a+b", Ok("a b".to_string())),
            ("a%20b", Ok("a b".to_string())),
            ("%25", Ok("%".to_string())),
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
                        out_value = Ok(tmp);
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
}