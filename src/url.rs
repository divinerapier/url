use std::{borrow::Cow, collections::HashMap, fmt::Display};

use crate::{escape, should_escape, unescape, Encoding, Error, Result};

#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct URL {
    scheme: String,
    opaque: String,
    user: Option<UserInfo>,
    host: String,
    path: String,
    raw_path: String,
    force_query: bool,
    raw_query: String,
    fragment: String,
    raw_fragment: String,
}

#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct UserInfo {
    username: Option<String>,
    password: Option<String>,
    password_set: bool,
}

impl UserInfo {
    pub fn user(username: String) -> UserInfo {
        UserInfo {
            username: Some(username),
            password: None,
            password_set: false,
        }
    }

    pub fn user_password(username: String, password: String) -> UserInfo {
        UserInfo {
            username: Some(username),
            password: Some(password),
            password_set: true,
        }
    }
}

impl Display for UserInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut u = match self.username {
            Some(ref username) => escape(username, Encoding::UserPassword),
            None => escape("", Encoding::UserPassword),
        };
        if self.password_set {
            u = u
                + ":"
                + &match self.password {
                    Some(ref password) => escape(password, Encoding::UserPassword),
                    None => escape("", Encoding::UserPassword),
                };
        }
        write!(f, "{}", u)
    }
}

fn split(s: &str, sep: char, cutc: bool) -> (&str, &str) {
    match s.find(sep) {
        Some(index) => {
            if cutc {
                (&s[0..index], &s[index + 1..])
            } else {
                (&s[0..index], &s[index..])
            }
        }
        None => (s, ""),
    }
}

fn string_contains_ctl_byte(s: &str) -> bool {
    let bytes = s.as_bytes();
    for &c in bytes {
        let c = c as char;
        if c < ' ' || c == 0x7f as char {
            return true;
        }
    }
    false
}

fn getscheme(rawurl: &str) -> Result<(Option<&str>, Option<&str>)> {
    let bytes = rawurl.as_bytes();

    for (index, c) in bytes.iter().enumerate() {
        let c = *c as char;
        match c {
            'a'..='z' | 'A'..='Z' => {}
            '0'..='9' | '+' | '-' | '.' => {
                if index == 0 {
                    return Ok((None, Some(rawurl)));
                }
            }
            ':' => {
                if index == 0 {
                    return Err(Error::MissingProtocolScheme);
                } else {
                    return Ok((Some(&rawurl[..index]), Some(&rawurl[index + 1..])));
                }
            }
            _ => return Ok((None, Some(rawurl))),
        }
    }

    Ok((None, Some(rawurl)))
}

impl URL {
    pub fn parse(rawurl: &str) -> Result<URL> {
        let (u, frag) = split(rawurl, '#', true);
        let mut url = Self::inner_parse(u, false)?;
        if frag.is_empty() {
            return Ok(url);
        }
        url.set_fragment(frag)?;
        Ok(url)
    }

    pub fn parse_request_uri(rawurl: &str) -> Result<URL> {
        Self::inner_parse(rawurl, true)
    }

    pub fn parse_reference(&self, refer: &str) -> Result<URL> {
        let refurl = Self::parse(refer)?;
        self.resolve_reference(&refurl)
    }

    fn inner_parse(rawurl: &str, via_request: bool) -> Result<URL> {
        if string_contains_ctl_byte(rawurl) {
            return Err(Error::InvalidControlCharacterInURL);
        }

        if rawurl.is_empty() && via_request {
            return Err(Error::EmptyURL);
        }

        let mut url = URL::default();

        if rawurl.eq("*") {
            url.path = "*".to_string();
            return Ok(url);
        }
        let (scheme, rest) = getscheme(rawurl)?;
        if let Some(scheme) = scheme {
            url.scheme = scheme.to_lowercase();
        }

        let rest = if let Some(mut rest) = rest {
            if rest.ends_with('?') && rest.matches('?').count() == 1 {
                url.force_query = true;
                rest = &rest[..rest.len() - 1];
            } else {
                let (rest_tmp, raw_query) = split(rest, '?', true);
                rest = rest_tmp;
                url.raw_query = raw_query.to_string();
            }

            println!("rest: {}", rest);
            println!("raw query: {}", url.raw_query);

            if !rest.starts_with('/') {
                if url.scheme.ne("") {
                    url.opaque = rest.to_string();
                    return Ok(url);
                }
                if via_request {
                    return Err(Error::InvalidURI(rest.to_string()));
                }
                let colon = rest.find(':');
                let slash = rest.find('/');
                match (colon, slash) {
                    (Some(colon), Some(slash)) => {
                        if colon < slash {
                            return Err(Error::NormalURL(String::from(
                                "first path segment in URL cannot contain colon",
                            )));
                        }
                    }
                    (Some(_), None) => {
                        return Err(Error::NormalURL(String::from(
                            "first path segment in URL cannot contain colon",
                        )))
                    }
                    (None, _) => {}
                }
            }
            if rest.starts_with("//")
                && ((!via_request && !rest.starts_with("///")) || (!url.scheme.is_empty()))
            {
                let (authority, rest_tmp) = split(&rest[2..], '/', false);
                rest = rest_tmp;
                let rh = parse_authority(authority)?;
                url.user = rh.0;
                url.host = rh.1.into();
            }
            rest
        } else {
            ""
        };
        url.set_path(rest)?;
        Ok(url)
    }

    fn set_path(&mut self, p: &str) -> Result<()> {
        let path = unescape(p, Encoding::Path)?;
        let escp = escape(&path, Encoding::Path);
        if escp.eq(p) {
            self.raw_path = "".to_string();
        } else {
            self.raw_path = p.to_string();
        }
        self.path = path.into();

        Ok(())
    }

    fn set_fragment(&mut self, f: &str) -> Result<()> {
        let frag = unescape(f, Encoding::Fragment)?;
        let escf = escape(&frag, Encoding::Fragment);
        if escf.eq(f) {
            self.raw_fragment = "".to_string();
        } else {
            self.raw_fragment = f.to_string();
        }
        self.fragment = frag.into();
        Ok(())
    }

    pub fn escaped_path(&self) -> String {
        if !self.raw_path.is_empty() && valid_encoded(&self.raw_path, Encoding::Path) {
            if let Ok(p) = unescape(&self.raw_path, Encoding::Path) {
                if p.eq(&self.path) {
                    return self.raw_path.clone();
                }
            }
        }

        if self.path.eq("*") {
            return "*".to_string();
        }

        escape(&self.path, Encoding::Path)
    }

    pub fn escaped_fragment(&self) -> String {
        if !self.raw_fragment.is_empty() && valid_encoded(&self.raw_fragment, Encoding::Fragment) {
            if let Ok(f) = unescape(&self.raw_fragment, Encoding::Fragment) {
                if f.eq(&self.fragment) {
                    return self.raw_fragment.clone();
                }
            }
        }
        escape(&self.fragment, Encoding::Fragment)
    }

    pub fn resolve_reference(&self, refer: &URL) -> Result<URL> {
        let mut url = refer.clone();
        if refer.scheme.is_empty() {
            url.scheme = self.scheme.clone();
        }
        if !refer.scheme.is_empty() || !refer.host.is_empty() || refer.user.is_some() {
            let resolved_path = resolve_path(&refer.escaped_path(), "");
            url.set_path(&resolved_path)?;
            return Ok(url);
        }
        if !refer.opaque.is_empty() {
            url.user = None;
            url.host = "".to_string();
            url.path = "".to_string();
            return Ok(url);
        }
        if refer.path.is_empty() && refer.raw_query.is_empty() {
            url.raw_query = self.raw_query.clone();
            if refer.fragment.is_empty() {
                url.fragment = self.fragment.clone();
                url.raw_fragment = self.raw_fragment.clone();
            }
        }

        url.host = self.host.clone();
        url.user = self.user.clone();
        url.set_path(&resolve_path(&self.escaped_path(), &refer.escaped_path()))?;
        Ok(url)
    }
}

impl Display for URL {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut buf = String::with_capacity(32);
        if !self.scheme.is_empty() {
            buf.push_str(&self.scheme);
            buf.push(':');
        }
        if !self.opaque.is_empty() {
            buf.push_str(&self.opaque);
        } else {
            if !self.scheme.is_empty() || !self.host.is_empty() || self.user.is_some() {
                if !self.host.is_empty() || !self.path.is_empty() || self.user.is_some() {
                    buf.push_str("//");
                }
                if let Some(ref ui) = self.user {
                    buf.push_str(&ui.to_string());
                }
                if !self.host.is_empty() {
                    buf.push_str(&escape(&self.host, Encoding::Host));
                }
            }
            let path = self.escaped_path();
            let path_bytes = path.as_bytes();
            if !path_bytes.is_empty() && path_bytes[0] != b'/' && !self.host.is_empty() {
                buf.push('/')
            }
            if buf.is_empty() {
                if let Some(i) = path.find(':') {
                    if (&path[..i]).find('/').is_none() {
                        buf.push_str("./");
                    }
                }
            }
            buf.push_str(&path);
        }

        if self.force_query || !self.raw_query.is_empty() {
            buf.push('?');
            buf.push_str(&self.raw_query);
        }
        if !self.fragment.is_empty() {
            buf.push('#');
            buf.push_str(&self.escaped_fragment());
        }

        write!(f, "{}", buf)
    }
}

fn resolve_path(base: &str, r: &str) -> String {
    let full = if r.is_empty() {
        base.to_string()
    } else if !r.starts_with('/') {
        let i = match base.rfind('/') {
            Some(i) => i + 1,
            None => 0,
        };
        println!("i: {}. len: {}", i, base.len());
        (&base[..i]).to_string() + r
    } else {
        r.to_string()
    };

    if full.is_empty() {
        return full;
    }

    let mut last: &str = "";
    let mut elem: &str;
    let mut i: i32 = 0;
    let mut dst = "/".to_string();

    let mut first = true;
    let mut remaining: &str = &full;

    while i >= 0 {
        match remaining.find('/') {
            Some(index) => {
                elem = &remaining[..index];
                remaining = &remaining[index + 1..];
                i = index as i32;
            }
            None => {
                last = remaining;
                elem = remaining;
                remaining = "";
                i = -1;
            }
        }
        if elem.eq(".") {
            first = false;
            continue;
        }

        if elem.eq("..") {
            let str = dst.clone();
            let index = str.rfind('/');
            dst.clear();
            if let Some(index) = index {
                dst.push_str(&str[..index]);
            } else {
                first = true;
            }
        } else {
            if !first {
                dst.push('/');
            }
            dst.push_str(elem);
            first = false;
        }
    }

    if last.eq(".") || last.eq("..") {
        dst.push('/')
    }

    if dst.starts_with("//") {
        (&dst[1..]).to_string()
    } else {
        dst
    }
}

fn parse_authority(authority: &str) -> Result<(Option<UserInfo>, Cow<str>)> {
    let i = authority.rfind('@');
    let host = match i {
        None => parse_host(authority)?,
        Some(i) => parse_host(&authority[i + 1..])?,
    };
    if i.is_none() {
        return Ok((None, host));
    }
    let i = i.unwrap();
    let userinfo = &authority[0..i];
    if !valid_userinfo(userinfo) {
        return Err(Error::InvalidUserInfo);
    }
    let user = if !userinfo.contains(':') {
        let username = unescape(userinfo, Encoding::UserPassword)?;
        UserInfo::user(username.into_owned())
    } else {
        let (username, password) = split(userinfo, ':', true);
        let username = unescape(username, Encoding::UserPassword)?;
        let password = unescape(password, Encoding::UserPassword)?;
        UserInfo::user_password(username.into_owned(), password.into_owned())
    };

    Ok((Some(user), host))
}

fn valid_userinfo(s: &str) -> bool {
    let s = s.as_bytes();
    for r in s {
        let r = *r as char;
        match r {
            'A'..='Z' | 'a'..='z' | '0'..='9' => continue,
            '-' | '.' | '_' | ':' | '~' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ','
            | ';' | '=' | '%' | '@' => continue,
            _ => return false,
        }
    }
    true
}

fn valid_optional_port(port: &str) -> bool {
    if port.is_empty() {
        return true;
    }
    if !port.starts_with(':') {
        return false;
    }
    let bytes = (&port[1..]).as_bytes();
    for c in bytes {
        let c = *c as char;
        if c < '0' || c > '9' {
            return false;
        }
    }
    true
}

fn valid_encoded(rawpath: &str, mode: Encoding) -> bool {
    let s = rawpath.as_bytes();
    for i in 0..s.len() {
        match s[i] as char {
            '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=' | ':' | '@' => {}
            '[' | ']' => {}
            '%' => {}
            _ => {
                if should_escape(s[i], mode) {
                    return false;
                }
            }
        }
    }
    true
}

fn parse_host<'a>(host: &'a str) -> Result<Cow<'a, str>> {
    println!("parse host input. {}", host);
    if host.starts_with('[') {
        let i = host.rfind(']');
        if i.is_none() {
            // TODO: handle error
            return Err(Error::InvalidHost(host.to_string()));
        }
        let i = i.unwrap();
        let colon_port = &host[i + 1..];
        if !valid_optional_port(colon_port) {
            // TODO: handle error
            return Err(Error::InvalidPort(colon_port.to_string()));
        }

        if let Some(zone) = (&host[..i]).find("%25") {
            let host1 = unescape(&host[..zone], Encoding::Host)?;
            let host2 = unescape(&host[zone..i], Encoding::Zone)?;
            let host3 = unescape(&host[i..], Encoding::Host)?;
            return Ok(Cow::Owned([host1, host2, host3].concat()));
        }
    } else if let Some(i) = host.find(':') {
        let colon_port = &host[i..];
        if !valid_optional_port(colon_port) {
            return Err(Error::InvalidPort(colon_port.to_string()));
        }
    }

    unescape(host, Encoding::Host)
}

pub struct Values<'a> {
    inner: HashMap<Cow<'a, str>, Vec<Cow<'a, str>>>,
}

impl<'a> Values<'a> {
    pub fn get(&self, key: &str) -> &str {
        if self.inner.is_empty() {
            return "";
        }

        if let Some(vs) = self.inner.get(key) {
            if vs.is_empty() {
                return "";
            } else {
                return &vs[0];
            }
        }
        ""
    }

    pub fn set(&mut self, key: Cow<'a, str>, value: Cow<'a, str>) {
        let v = self.inner.entry(key).or_insert_with(Vec::new);
        if !v.is_empty() {
            v.clear();
        }
        v.push(value);
    }

    pub fn add(&mut self, key: Cow<'a, str>, value: Cow<'a, str>) {
        let v = self.inner.entry(key).or_insert_with(Vec::new);
        v.push(value);
    }

    pub fn delete(&mut self, key: Cow<'a, str>) {
        if self.inner.contains_key(&key) {
            self.inner.remove(&key);
        }
    }
}

fn parse_query(query: &str) -> Result<Option<()>> {
    if query.is_empty() {
        return Ok(None);
    }
    Ok(None)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_url() {
        let cases = vec![
            (
                "http://www.google.com",
                URL {
                    scheme: "http".to_string(),
                    host: "www.google.com".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // path
            (
                "http://www.google.com/",
                URL {
                    scheme: "http".to_string(),
                    host: "www.google.com".to_string(),
                    path: "/".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // path with hex escaping
            (
                "http://www.google.com/file%20one%26two",
                URL {
                    scheme: "http".to_string(),
                    host: "www.google.com".to_string(),
                    path: "/file one&two".to_string(),
                    raw_path: "/file%20one%26two".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // fragment with hex escaping
            (
                "http://www.google.com/#file%20one%26two",
                URL {
                    scheme: "http".to_string(),
                    host: "www.google.com".to_string(),
                    path: "/".to_string(),
                    fragment: "file one&two".to_string(),
                    raw_fragment: "file%20one%26two".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // user
            (
                "ftp://webmaster@www.google.com/",
                URL {
                    scheme: "ftp".to_string(),
                    user: Some(UserInfo::user("webmaster".to_string())),
                    host: "www.google.com".to_string(),
                    path: "/".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // escape sequence in username
            (
                "ftp://john%20doe@www.google.com/",
                URL {
                    scheme: "ftp".to_string(),
                    user: Some(UserInfo::user("john doe".to_string())),
                    host: "www.google.com".to_string(),
                    path: "/".to_string(),
                    ..Default::default()
                },
                "ftp://john%20doe@www.google.com/",
            ),
            // empty query
            (
                "http://www.google.com/?",
                URL {
                    scheme: "http".to_string(),
                    host: "www.google.com".to_string(),
                    path: "/".to_string(),
                    force_query: true,
                    ..Default::default()
                },
                "",
            ),
            // query ending in question mark (Issue 14573)
            (
                "http://www.google.com/?foo=bar?",
                URL {
                    scheme: "http".to_string(),
                    host: "www.google.com".to_string(),
                    path: "/".to_string(),
                    raw_query: "foo=bar?".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // query
            (
                "http://www.google.com/?q=go+language",
                URL {
                    scheme: "http".to_string(),
                    host: "www.google.com".to_string(),
                    path: "/".to_string(),
                    raw_query: "q=go+language".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // query with hex escaping: NOT parsed
            (
                "http://www.google.com/?q=go%20language",
                URL {
                    scheme: "http".to_string(),
                    host: "www.google.com".to_string(),
                    path: "/".to_string(),
                    raw_query: "q=go%20language".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // %20 outside query
            (
                "http://www.google.com/a%20b?q=c+d",
                URL {
                    scheme: "http".to_string(),
                    host: "www.google.com".to_string(),
                    path: "/a b".to_string(),
                    raw_query: "q=c+d".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // path without leading /, so no parsing
            (
                "http:www.google.com/?q=go+language",
                URL {
                    scheme: "http".to_string(),
                    opaque: "www.google.com/".to_string(),
                    raw_query: "q=go+language".to_string(),
                    ..Default::default()
                },
                "http:www.google.com/?q=go+language",
            ),
            // path without leading /, so no parsing
            (
                "http:%2f%2fwww.google.com/?q=go+language",
                URL {
                    scheme: "http".to_string(),
                    opaque: "%2f%2fwww.google.com/".to_string(),
                    raw_query: "q=go+language".to_string(),
                    ..Default::default()
                },
                "http:%2f%2fwww.google.com/?q=go+language",
            ),
            // non-authority with path
            (
                "mailto:/webmaster@golang.org",
                URL {
                    scheme: "mailto".to_string(),
                    path: "/webmaster@golang.org".to_string(),
                    ..Default::default()
                },
                "mailto:///webmaster@golang.org", // unfortunate compromise
            ),
            // non-authority
            (
                "mailto:webmaster@golang.org",
                URL {
                    scheme: "mailto".to_string(),
                    opaque: "webmaster@golang.org".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // unescaped :// in query should not create a scheme
            (
                "/foo?query=http://bad",
                URL {
                    path: "/foo".to_string(),
                    raw_query: "query=http://bad".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // leading // without scheme should create an authority
            (
                "//foo",
                URL {
                    host: "foo".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // leading // without scheme, with userinfo, path, and query
            (
                "//user@foo/path?a=b",
                URL {
                    user: Some(UserInfo::user("user".to_string())),
                    host: "foo".to_string(),
                    path: "/path".to_string(),
                    raw_query: "a=b".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // Three leading slashes isn't an authority, but doesn't return an error.
            // (We can't return an error, as this code is also used via
            // ServeHTTP -> ReadRequest -> Parse, which is arguably a
            // different URL parsing context, but currently shares the
            // same codepath)
            (
                "///threeslashes",
                URL {
                    path: "///threeslashes".to_string(),
                    ..Default::default()
                },
                "",
            ),
            (
                "http://user:password@google.com",
                URL {
                    scheme: "http".to_string(),
                    user: Some(UserInfo::user_password(
                        "user".to_string(),
                        "password".to_string(),
                    )),
                    host: "google.com".to_string(),
                    ..Default::default()
                },
                "http://user:password@google.com",
            ),
            // unescaped @ in username should not confuse host
            (
                "http://j@ne:password@google.com",
                URL {
                    scheme: "http".to_string(),
                    user: Some(UserInfo::user_password(
                        "j@ne".to_string(),
                        "password".to_string(),
                    )),
                    host: "google.com".to_string(),
                    ..Default::default()
                },
                "http://j%40ne:password@google.com",
            ),
            // unescaped @ in password should not confuse host
            (
                "http://jane:p@ssword@google.com",
                URL {
                    scheme: "http".to_string(),
                    user: Some(UserInfo::user_password(
                        "jane".to_string(),
                        "p@ssword".to_string(),
                    )),
                    host: "google.com".to_string(),
                    ..Default::default()
                },
                "http://jane:p%40ssword@google.com",
            ),
            (
                "http://j@ne:password@google.com/p@th?q=@go",
                URL {
                    scheme: "http".to_string(),
                    user: Some(UserInfo::user_password(
                        "j@ne".to_string(),
                        "password".to_string(),
                    )),
                    host: "google.com".to_string(),
                    path: "/p@th".to_string(),
                    raw_query: "q=@go".to_string(),
                    ..Default::default()
                },
                "http://j%40ne:password@google.com/p@th?q=@go",
            ),
            (
                "http://www.google.com/?q=go+language#foo",
                URL {
                    scheme: "http".to_string(),
                    host: "www.google.com".to_string(),
                    path: "/".to_string(),
                    raw_query: "q=go+language".to_string(),
                    fragment: "foo".to_string(),
                    ..Default::default()
                },
                "",
            ),
            (
                "http://www.google.com/?q=go+language#foo&bar",
                URL {
                    scheme: "http".to_string(),
                    host: "www.google.com".to_string(),
                    path: "/".to_string(),
                    raw_query: "q=go+language".to_string(),
                    fragment: "foo&bar".to_string(),
                    ..Default::default()
                },
                "http://www.google.com/?q=go+language#foo&bar",
            ),
            (
                "http://www.google.com/?q=go+language#foo%26bar",
                URL {
                    scheme: "http".to_string(),
                    host: "www.google.com".to_string(),
                    path: "/".to_string(),
                    raw_query: "q=go+language".to_string(),
                    fragment: "foo&bar".to_string(),
                    raw_fragment: "foo%26bar".to_string(),
                    ..Default::default()
                },
                "http://www.google.com/?q=go+language#foo%26bar",
            ),
            (
                "file:///home/adg/rabbits",
                URL {
                    scheme: "file".to_string(),
                    host: "".to_string(),
                    path: "/home/adg/rabbits".to_string(),
                    ..Default::default()
                },
                "file:///home/adg/rabbits",
            ),
            // "Windows" paths are no exception to the rule.
            // See golang.org/issue/6027, especially comment #9.
            (
                "file:///C:/FooBar/Baz.txt",
                URL {
                    scheme: "file".to_string(),
                    host: "".to_string(),
                    path: "/C:/FooBar/Baz.txt".to_string(),
                    ..Default::default()
                },
                "file:///C:/FooBar/Baz.txt",
            ),
            // case-insensitive scheme
            (
                "MaIlTo:webmaster@golang.org",
                URL {
                    scheme: "mailto".to_string(),
                    opaque: "webmaster@golang.org".to_string(),
                    ..Default::default()
                },
                "mailto:webmaster@golang.org",
            ),
            // Relative path
            (
                "a/b/c",
                URL {
                    path: "a/b/c".to_string(),
                    ..Default::default()
                },
                "a/b/c",
            ),
            // escaped '?' in username and password
            (
                "http://%3Fam:pa%3Fsword@google.com",
                URL {
                    scheme: "http".to_string(),
                    user: Some(UserInfo::user_password(
                        "?am".to_string(),
                        "pa?sword".to_string(),
                    )),
                    host: "google.com".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // host subcomponent; IPv4 address in RFC 3986
            (
                "http://192.168.0.1/",
                URL {
                    scheme: "http".to_string(),
                    host: "192.168.0.1".to_string(),
                    path: "/".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // host and port subcomponents; IPv4 address in RFC 3986
            (
                "http://192.168.0.1:8080/",
                URL {
                    scheme: "http".to_string(),
                    host: "192.168.0.1:8080".to_string(),
                    path: "/".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // host subcomponent; IPv6 address in RFC 3986
            (
                "http://[fe80::1]/",
                URL {
                    scheme: "http".to_string(),
                    host: "[fe80::1]".to_string(),
                    path: "/".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // host and port subcomponents; IPv6 address in RFC 3986
            (
                "http://[fe80::1]:8080/",
                URL {
                    scheme: "http".to_string(),
                    host: "[fe80::1]:8080".to_string(),
                    path: "/".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // host subcomponent; IPv6 address with zone identifier in RFC 6874
            (
                "http://[fe80::1%25en0]/", // alphanum zone identifier
                URL {
                    scheme: "http".to_string(),
                    host: "[fe80::1%en0]".to_string(),
                    path: "/".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // host and port subcomponents; IPv6 address with zone identifier in RFC 6874
            (
                "http://[fe80::1%25en0]:8080/", // alphanum zone identifier
                URL {
                    scheme: "http".to_string(),
                    host: "[fe80::1%en0]:8080".to_string(),
                    path: "/".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // host subcomponent; IPv6 address with zone identifier in RFC 6874
            (
                "http://[fe80::1%25%65%6e%301-._~]/", // percent-encoded+unreserved zone identifier
                URL {
                    scheme: "http".to_string(),
                    host: "[fe80::1%en01-._~]".to_string(),
                    path: "/".to_string(),
                    ..Default::default()
                },
                "http://[fe80::1%25en01-._~]/",
            ),
            // host and port subcomponents; IPv6 address with zone identifier in RFC 6874
            (
                "http://[fe80::1%25%65%6e%301-._~]:8080/", // percent-encoded+unreserved zone identifier
                URL {
                    scheme: "http".to_string(),
                    host: "[fe80::1%en01-._~]:8080".to_string(),
                    path: "/".to_string(),
                    ..Default::default()
                },
                "http://[fe80::1%25en01-._~]:8080/",
            ),
            // alternate escapings of path survive round trip
            (
                "http://rest.rsc.io/foo%2fbar/baz%2Fquux?alt=media",
                URL {
                    scheme: "http".to_string(),
                    host: "rest.rsc.io".to_string(),
                    path: "/foo/bar/baz/quux".to_string(),
                    raw_path: "/foo%2fbar/baz%2Fquux".to_string(),
                    raw_query: "alt=media".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // issue 12036
            (
                "mysql://a,b,c/bar",
                URL {
                    scheme: "mysql".to_string(),
                    host: "a,b,c".to_string(),
                    path: "/bar".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // worst case host, still round trips
            (
                "scheme://!$&'()*+,;=hello!:1/path",
                URL {
                    scheme: "scheme".to_string(),
                    host: "!$&'()*+,;=hello!:1".to_string(),
                    path: "/path".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // worst case path, still round trips
            (
                "http://host/!$&'()*+,;=:@[hello]",
                URL {
                    scheme: "http".to_string(),
                    host: "host".to_string(),
                    path: "/!$&'()*+,;=:@[hello]".to_string(),
                    raw_path: "/!$&'()*+,;=:@[hello]".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // golang.org/issue/5684
            (
                "http://example.com/oid/[order_id]",
                URL {
                    scheme: "http".to_string(),
                    host: "example.com".to_string(),
                    path: "/oid/[order_id]".to_string(),
                    raw_path: "/oid/[order_id]".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // golang.org/issue/12200 (colon with empty port)
            (
                "http://192.168.0.2:8080/foo",
                URL {
                    scheme: "http".to_string(),
                    host: "192.168.0.2:8080".to_string(),
                    path: "/foo".to_string(),
                    ..Default::default()
                },
                "",
            ),
            (
                "http://192.168.0.2:/foo",
                URL {
                    scheme: "http".to_string(),
                    host: "192.168.0.2:".to_string(),
                    path: "/foo".to_string(),
                    ..Default::default()
                },
                "",
            ),
            (
                // Malformed IPv6 but still accepted.
                "http://2b01:e34:ef40:7730:8e70:5aff:fefe:edac:8080/foo",
                URL {
                    scheme: "http".to_string(),
                    host: "2b01:e34:ef40:7730:8e70:5aff:fefe:edac:8080".to_string(),
                    path: "/foo".to_string(),
                    ..Default::default()
                },
                "",
            ),
            (
                // Malformed IPv6 but still accepted.
                "http://2b01:e34:ef40:7730:8e70:5aff:fefe:edac:/foo",
                URL {
                    scheme: "http".to_string(),
                    host: "2b01:e34:ef40:7730:8e70:5aff:fefe:edac:".to_string(),
                    path: "/foo".to_string(),
                    ..Default::default()
                },
                "",
            ),
            (
                "http://[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:8080/foo",
                URL {
                    scheme: "http".to_string(),
                    host: "[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:8080".to_string(),
                    path: "/foo".to_string(),
                    ..Default::default()
                },
                "",
            ),
            (
                "http://[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:/foo",
                URL {
                    scheme: "http".to_string(),
                    host: "[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:".to_string(),
                    path: "/foo".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // golang.org/issue/10433 (path beginning with //)
            (
                "http://example.com//foo",
                URL {
                    scheme: "http".to_string(),
                    host: "example.com".to_string(),
                    path: "//foo".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // test that we can reparse the host names we accept.
            (
                "myscheme://authority<\"hi\">/foo",
                URL {
                    scheme: "myscheme".to_string(),
                    host: "authority<\"hi\">".to_string(),
                    path: "/foo".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // spaces in hosts are disallowed but escaped spaces in IPv6 scope IDs are grudgingly OK.
            // This happens on Windows.
            // golang.org/issue/14002
            (
                "tcp://[2020::2020:20:2020:2020%25Windows%20Loves%20Spaces]:2020",
                URL {
                    scheme: "tcp".to_string(),
                    host: "[2020::2020:20:2020:2020%Windows Loves Spaces]:2020".to_string(),
                    ..Default::default()
                },
                "",
            ),
            // test we can roundtrip magnet url
            // fix issue https://golang.org/issue/20054
            (
                "magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn",
                URL {
                    scheme: "magnet".to_string(),
                    host: "".to_string(),
                    path: "".to_string(),
                    raw_query: "xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn"
                        .to_string(),
                    ..Default::default()
                },
                "magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn",
            ),
            (
                "mailto:?subject=hi",
                URL {
                    scheme: "mailto".to_string(),
                    host: "".to_string(),
                    path: "".to_string(),
                    raw_query: "subject=hi".to_string(),
                    ..Default::default()
                },
                "mailto:?subject=hi",
            ),
        ];

        for case in cases {
            println!("parse {}", case.0);
            match URL::parse(case.0) {
                Err(e) => {
                    println!("input: {:?}. error: {}", case, e);
                }
                Ok(u) => {
                    assert_eq!(u, case.1);
                }
            }
        }
    }

    #[test]
    fn test_parse_utf8_url() {
        let cases = vec![
            // golang.org/issue/7991 and golang.org/issue/12719 (non-ascii %-encoded in host)
            (
                "http://hello.世界.com/foo",
                URL {
                    scheme: "http".to_string(),
                    host: "hello.世界.com".to_string(),
                    path: "/foo".to_string(),
                    ..Default::default()
                },
                "http://hello.%E4%B8%96%E7%95%8C.com/foo",
            ),
            (
                "http://hello.%e4%b8%96%e7%95%8c.com/foo",
                URL {
                    scheme: "http".to_string(),
                    host: "hello.世界.com".to_string(),
                    path: "/foo".to_string(),
                    ..Default::default()
                },
                "http://hello.%E4%B8%96%E7%95%8C.com/foo",
            ),
            (
                "http://hello.%E4%B8%96%E7%95%8C.com/foo",
                URL {
                    scheme: "http".to_string(),
                    host: "hello.世界.com".to_string(),
                    path: "/foo".to_string(),
                    ..Default::default()
                },
                "",
            ),
        ];
        for case in cases {
            println!("parse {}", case.0);
            match URL::parse(case.0) {
                Err(e) => {
                    println!("input: {:?}. error: {}", case, e);
                }
                Ok(u) => {
                    assert_eq!(u, case.1);
                }
            }
        }
    }

    #[test]
    fn test_parse_host() {
        let cases = vec![("hello.%e4%b8%96%e7%95%8c.com", "hello.世界.com")];
        for case in cases {
            let output = parse_host(case.0);
            assert_eq!(output, Ok(Cow::Owned(case.1.to_string())));
        }
    }

    #[test]
    fn test_string_utf8() {
        let s = "hello.世界.com";
        println!("{}", s);
        for c in s.as_bytes() {
            print!("{}, ", *c as u32);
        }
        println!();
        for c in s.chars() {
            print!("{}, ", c as u32);
        }
        println!();
        // 104, 101, 108, 108, 111, 46, 228, 184, 150, 231, 149, 140, 46, 99, 111, 109,
        let v = vec![
            104, 101, 108, 108, 111, 46, 228, 184, 150, 231, 149, 140, 46, 99, 111, 109,
        ];
        let a = String::from_utf8_lossy(&v);
        println!("{}", a);
        let v2 = vec![
            104, 101, 108, 108, 111, 46, 228, 184, 150, 231, 149, 140, 46, 99, 111, 109,
        ];
        let a2 = String::from_utf8_lossy(&v2);
        println!("{}", a2);

        let s = "hello.ä¸ç.com";
        println!("{}", s);
        for c in s.as_bytes() {
            print!("{}, ", *c as u32);
        }
        println!();
    }

    #[test]
    fn test_resolve_path() {
        let cases = vec![
            ("a/b", ".", "/a/"),
            ("a/b", "c", "/a/c"),
            ("a/b", "..", "/"),
            ("a/", "..", "/"),
            ("a/", "../..", "/"),
            ("a/b/c", "..", "/a/"),
            ("a/b/c", "../d", "/a/d"),
            ("a/b/c", ".././d", "/a/d"),
            ("a/b", "./..", "/"),
            ("a/./b", ".", "/a/"),
            ("a/../", ".", "/"),
            ("a/.././b", "c", "/c"),
        ];
        for (base, refer, expected) in cases {
            let got = resolve_path(base, refer);
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn test_resolve_reference() {
        let cases = vec![
            // Absolute URL references
            ("http://foo.com?a=b", "https://bar.com/", "https://bar.com/"),
            (
                "http://foo.com/",
                "https://bar.com/?a=b",
                "https://bar.com/?a=b",
            ),
            ("http://foo.com/", "https://bar.com/?", "https://bar.com/?"),
            (
                "http://foo.com/bar",
                "mailto:foo@example.com",
                "mailto:foo@example.com",
            ),
            // Path-absolute references
            ("http://foo.com/bar", "/baz", "http://foo.com/baz"),
            ("http://foo.com/bar?a=b#f", "/baz", "http://foo.com/baz"),
            ("http://foo.com/bar?a=b", "/baz?", "http://foo.com/baz?"),
            (
                "http://foo.com/bar?a=b",
                "/baz?c=d",
                "http://foo.com/baz?c=d",
            ),
            // Multiple slashes
            (
                "http://foo.com/bar",
                "http://foo.com//baz",
                "http://foo.com//baz",
            ),
            (
                "http://foo.com/bar",
                "http://foo.com///baz/quux",
                "http://foo.com///baz/quux",
            ),
            // Scheme-relative
            (
                "https://foo.com/bar?a=b",
                "//bar.com/quux",
                "https://bar.com/quux",
            ),
            // Path-relative references:

            // ... current directory
            ("http://foo.com", ".", "http://foo.com/"),
            ("http://foo.com/bar", ".", "http://foo.com/"),
            ("http://foo.com/bar/", ".", "http://foo.com/bar/"),
            // ... going down
            ("http://foo.com", "bar", "http://foo.com/bar"),
            ("http://foo.com/", "bar", "http://foo.com/bar"),
            ("http://foo.com/bar/baz", "quux", "http://foo.com/bar/quux"),
            // ... going up
            ("http://foo.com/bar/baz", "../quux", "http://foo.com/quux"),
            (
                "http://foo.com/bar/baz",
                "../../../../../quux",
                "http://foo.com/quux",
            ),
            ("http://foo.com/bar", "..", "http://foo.com/"),
            ("http://foo.com/bar/baz", "./..", "http://foo.com/"),
            // ".." in the middle (issue 3560)
            (
                "http://foo.com/bar/baz",
                "quux/dotdot/../tail",
                "http://foo.com/bar/quux/tail",
            ),
            (
                "http://foo.com/bar/baz",
                "quux/./dotdot/../tail",
                "http://foo.com/bar/quux/tail",
            ),
            (
                "http://foo.com/bar/baz",
                "quux/./dotdot/.././tail",
                "http://foo.com/bar/quux/tail",
            ),
            (
                "http://foo.com/bar/baz",
                "quux/./dotdot/./../tail",
                "http://foo.com/bar/quux/tail",
            ),
            (
                "http://foo.com/bar/baz",
                "quux/./dotdot/dotdot/././../../tail",
                "http://foo.com/bar/quux/tail",
            ),
            (
                "http://foo.com/bar/baz",
                "quux/./dotdot/dotdot/./.././../tail",
                "http://foo.com/bar/quux/tail",
            ),
            (
                "http://foo.com/bar/baz",
                "quux/./dotdot/dotdot/dotdot/./../../.././././tail",
                "http://foo.com/bar/quux/tail",
            ),
            (
                "http://foo.com/bar/baz",
                "quux/./dotdot/../dotdot/../dot/./tail/..",
                "http://foo.com/bar/quux/dot/",
            ),
            // Remove any dot-segments prior to forming the target URI.
            // http://tools.ietf.org/html/rfc3986#section-5.2.4
            (
                "http://foo.com/dot/./dotdot/../foo/bar",
                "../baz",
                "http://foo.com/dot/baz",
            ),
            // Triple dot isn't special
            ("http://foo.com/bar", "...", "http://foo.com/..."),
            // Fragment
            ("http://foo.com/bar", ".#frag", "http://foo.com/#frag"),
            (
                "http://example.org/",
                "#!$&%27()*+,;=",
                "http://example.org/#!$&%27()*+,;=",
            ),
            // Paths with escaping (issue 16947).
            ("http://foo.com/foo%2fbar/", "../baz", "http://foo.com/baz"),
            (
                "http://foo.com/1/2%2f/3%2f4/5",
                "../../a/b/c",
                "http://foo.com/1/a/b/c",
            ),
            (
                "http://foo.com/1/2/3",
                "./a%2f../../b/..%2fc",
                "http://foo.com/1/2/b/..%2fc",
            ),
            (
                "http://foo.com/1/2%2f/3%2f4/5",
                "./a%2f../b/../c",
                "http://foo.com/1/2%2f/3%2f4/a%2f../c",
            ),
            ("http://foo.com/foo%20bar/", "../baz", "http://foo.com/baz"),
            (
                "http://foo.com/foo",
                "../bar%2fbaz",
                "http://foo.com/bar%2fbaz",
            ),
            (
                "http://foo.com/foo%2dbar/",
                "./baz-quux",
                "http://foo.com/foo%2dbar/baz-quux",
            ),
            // RFC 3986: Normal Examples
            // http://tools.ietf.org/html/rfc3986#section-5.4.1
            ("http://a/b/c/d;p?q", "g:h", "g:h"),
            ("http://a/b/c/d;p?q", "g", "http://a/b/c/g"),
            ("http://a/b/c/d;p?q", "./g", "http://a/b/c/g"),
            ("http://a/b/c/d;p?q", "g/", "http://a/b/c/g/"),
            ("http://a/b/c/d;p?q", "/g", "http://a/g"),
            ("http://a/b/c/d;p?q", "//g", "http://g"),
            ("http://a/b/c/d;p?q", "?y", "http://a/b/c/d;p?y"),
            ("http://a/b/c/d;p?q", "g?y", "http://a/b/c/g?y"),
            ("http://a/b/c/d;p?q", "#s", "http://a/b/c/d;p?q#s"),
            ("http://a/b/c/d;p?q", "g#s", "http://a/b/c/g#s"),
            ("http://a/b/c/d;p?q", "g?y#s", "http://a/b/c/g?y#s"),
            ("http://a/b/c/d;p?q", ";x", "http://a/b/c/;x"),
            ("http://a/b/c/d;p?q", "g;x", "http://a/b/c/g;x"),
            ("http://a/b/c/d;p?q", "g;x?y#s", "http://a/b/c/g;x?y#s"),
            ("http://a/b/c/d;p?q", "", "http://a/b/c/d;p?q"),
            ("http://a/b/c/d;p?q", ".", "http://a/b/c/"),
            ("http://a/b/c/d;p?q", "./", "http://a/b/c/"),
            ("http://a/b/c/d;p?q", "..", "http://a/b/"),
            ("http://a/b/c/d;p?q", "../", "http://a/b/"),
            ("http://a/b/c/d;p?q", "../g", "http://a/b/g"),
            ("http://a/b/c/d;p?q", "../..", "http://a/"),
            ("http://a/b/c/d;p?q", "../../", "http://a/"),
            ("http://a/b/c/d;p?q", "../../g", "http://a/g"),
            // RFC 3986: Abnormal Examples
            // http://tools.ietf.org/html/rfc3986#section-5.4.2
            ("http://a/b/c/d;p?q", "../../../g", "http://a/g"),
            ("http://a/b/c/d;p?q", "../../../../g", "http://a/g"),
            ("http://a/b/c/d;p?q", "/./g", "http://a/g"),
            ("http://a/b/c/d;p?q", "/../g", "http://a/g"),
            ("http://a/b/c/d;p?q", "g.", "http://a/b/c/g."),
            ("http://a/b/c/d;p?q", ".g", "http://a/b/c/.g"),
            ("http://a/b/c/d;p?q", "g..", "http://a/b/c/g.."),
            ("http://a/b/c/d;p?q", "..g", "http://a/b/c/..g"),
            ("http://a/b/c/d;p?q", "./../g", "http://a/b/g"),
            ("http://a/b/c/d;p?q", "./g/.", "http://a/b/c/g/"),
            ("http://a/b/c/d;p?q", "g/./h", "http://a/b/c/g/h"),
            ("http://a/b/c/d;p?q", "g/../h", "http://a/b/c/h"),
            ("http://a/b/c/d;p?q", "g;x=1/./y", "http://a/b/c/g;x=1/y"),
            ("http://a/b/c/d;p?q", "g;x=1/../y", "http://a/b/c/y"),
            ("http://a/b/c/d;p?q", "g?y/./x", "http://a/b/c/g?y/./x"),
            ("http://a/b/c/d;p?q", "g?y/../x", "http://a/b/c/g?y/../x"),
            ("http://a/b/c/d;p?q", "g#s/./x", "http://a/b/c/g#s/./x"),
            ("http://a/b/c/d;p?q", "g#s/../x", "http://a/b/c/g#s/../x"),
            // Extras.
            ("https://a/b/c/d;p?q", "//g?q", "https://g?q"),
            ("https://a/b/c/d;p?q", "//g#s", "https://g#s"),
            (
                "https://a/b/c/d;p?q",
                "//g/d/e/f?y#s",
                "https://g/d/e/f?y#s",
            ),
            ("https://a/b/c/d;p#s", "?y", "https://a/b/c/d;p?y"),
            ("https://a/b/c/d;p?q#s", "?y", "https://a/b/c/d;p?y"),
        ];

        let opaque = URL {
            scheme: "scheme".to_string(),
            opaque: "opaque".to_string(),
            ..Default::default()
        };
        for (base, refer, expected) in cases {
            let b = URL::parse(base).expect(&format!("parse {}", base));
            let r = URL::parse(refer).expect(&format!("parse {}", refer));
            let url = b.resolve_reference(&r).unwrap();
            let got = url.to_string();
            assert_eq!(got, expected);
            let url = b.parse_reference(refer).unwrap();
            let got = url.to_string();
            assert_eq!(got, expected);
            let url = b.resolve_reference(&opaque).unwrap();
            assert_eq!(url, opaque);
            let url = b.parse_reference("scheme:opaque").unwrap();
            assert_ne!(url, b);
        }
    }

    #[test]
    fn test_index_any() {
        let a = "abcdefg1234567hijk";
        // a.matches(|c| {})
    }
}
