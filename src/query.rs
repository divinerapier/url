use std::{borrow::Cow, collections::HashMap, convert::TryFrom, iter::FromIterator, str::FromStr};

use crate::{errors::Error, query_unescape, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Values<'a> {
    inner: HashMap<Cow<'a, str>, Vec<Cow<'a, str>>>,
}

pub struct Pair<'a>(String, &'a Vec<Cow<'a, str>>);

pub struct PairIterator<'a> {
    key: String,
    values: &'a [Cow<'a, str>],
    current_index: usize,
}

impl<'a> Iterator for PairIterator<'a> {
    type Item = (String, &'a Cow<'a, str>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index >= self.values.len() {
            None
        } else {
            let result = &self.values[self.current_index];
            self.current_index += 1;
            Some((self.key.clone(), result))
        }
    }
}

impl<'a> IntoIterator for Pair<'a> {
    type Item = (String, &'a Cow<'a, str>);

    type IntoIter = PairIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        PairIterator {
            key: self.0,
            values: self.1,
            current_index: 0,
        }
    }
}

impl<'a> Values<'a> {
    pub fn encode(&self) -> String {
        // Unsorted version
        // self.inner
        //     .iter()
        //     .map(|(a, b)| (super::query_escape(a), b))
        //     .map(|(a, b)| Pair(a.to_string(), b))
        //     .flatten()
        //     .map(|(k, v)| {
        //         let k: String = k;
        //         let v = super::query_escape(&v);
        //         k + "=" + &v
        //     })
        //     .collect::<Vec<String>>()
        //     .join("&")

        let mut keys = self
            .inner
            .keys()
            .map(|key| (super::query_escape(key).to_string()))
            .collect::<Vec<String>>();
        keys.sort();
        let mut pairs = vec![];
        for key in keys.iter() {
            let str_key: &str = key;
            let values = self.inner.get(&Cow::Borrowed(str_key)).unwrap();
            for value in values {
                let value = super::query_escape(value);
                pairs.push((str_key, value));
            }
        }
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&")
    }
}

impl<'a> TryFrom<&'a str> for Values<'a> {
    type Error = Error;

    fn try_from(query: &'a str) -> Result<Self> {
        parse_query(query)
    }
}

impl<'a> FromIterator<(Cow<'a, str>, Vec<Cow<'a, str>>)> for Values<'a> {
    fn from_iter<T: IntoIterator<Item = (Cow<'a, str>, Vec<Cow<'a, str>>)>>(iter: T) -> Self {
        let inner = HashMap::from_iter(iter);
        Values { inner }
    }
}

fn parse_query<'a>(query: &'a str) -> Result<Values<'a>> {
    let mut query = query;
    let mut inner = HashMap::<Cow<'a, str>, Vec<Cow<'a, str>>>::new();

    while !query.is_empty() {
        let mut key = query;
        match query.find('&') {
            Some(index) => {
                key = &key[..index];
                query = &query[index + 1..];
            }
            None => {
                query = "";
            }
        }
        if key.contains(';') {
            // TODO: err = fmt.Errorf("invalid semicolon separator in query")
            // continue;
            return Err(Error::InvalidSemicolonSeparatorInQuery);
        }
        if key.is_empty() {
            continue;
        }
        let mut value = "";
        if let Some(index) = key.find('=') {
            value = &key[index + 1..];
            key = &key[..index];
        }
        // TODO:
        // if err1 != nil {
        // 	if err == nil {
        // 		err = err1
        // 	}
        // 	continue
        // }
        let key = query_unescape(key)?;
        let value = query_unescape(value)?;
        inner.entry(key).or_default().push(value);
    }

    Ok(Values { inner })
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::convert::TryInto;
    use std::iter::FromIterator;

    use crate::query::Values;

    #[test]
    fn test_parse() {
        let tests = vec![
            (
                "a=1",
                Values::from_iter(vec![(Cow::Borrowed("a"), vec![Cow::Borrowed("1")])]),
                true,
            ),
            (
                "a=1&b=2",
                Values::from_iter(vec![
                    (Cow::Borrowed("a"), vec![Cow::Borrowed("1")]),
                    (Cow::Borrowed("b"), vec![Cow::Borrowed("2")]),
                ]),
                true,
            ),
            (
                "a=1&a=2&a=banana",
                Values::from_iter(vec![(
                    Cow::Borrowed("a"),
                    vec![
                        Cow::Borrowed("1"),
                        Cow::Borrowed("2"),
                        Cow::Borrowed("banana"),
                    ],
                )]),
                true,
            ),
            (
                "ascii=%3Ckey%3A+0x90%3E",
                Values::from_iter(vec![(
                    Cow::Borrowed("ascii"),
                    vec![Cow::Borrowed("<key: 0x90>")],
                )]),
                true,
            ),
            ("a=1;b=2", Values::from_iter(vec![]), false),
            ("a;b=2", Values::from_iter(vec![]), false),
            (
                "a=%3B",
                Values::from_iter(vec![(Cow::Borrowed("a"), vec![Cow::Borrowed(";")])]),
                true,
            ),
            (
                "a%3Bb=1",
                Values::from_iter(vec![(Cow::Borrowed("a;b"), vec![Cow::Borrowed("1")])]),
                true,
            ),
            (
                "a=1&a=2;a=banana",
                Values::from_iter(vec![(Cow::Borrowed("a"), vec![Cow::Borrowed("1")])]),
                false,
            ),
            (
                "a;b&c=1",
                Values::from_iter(vec![(Cow::Borrowed("c"), vec![Cow::Borrowed("1")])]),
                false,
            ),
            (
                "a=1&b=2;a=3&c=4",
                Values::from_iter(vec![
                    (Cow::Borrowed("a"), vec![Cow::Borrowed("1")]),
                    (Cow::Borrowed("c"), vec![Cow::Borrowed("4")]),
                ]),
                false,
            ),
            (
                "a=1&b=2;c=3",
                Values::from_iter(vec![(Cow::Borrowed("a"), vec![Cow::Borrowed("1")])]),
                false,
            ),
            (";", Values::from_iter(vec![]), false),
            (
                "a=1&;",
                Values::from_iter(vec![(Cow::Borrowed("a"), vec![Cow::Borrowed("1")])]),
                false,
            ),
            (
                ";a=1&b=2",
                Values::from_iter(vec![(Cow::Borrowed("b"), vec![Cow::Borrowed("2")])]),
                false,
            ),
            (
                "a=1&b=2;",
                Values::from_iter(vec![(Cow::Borrowed("a"), vec![Cow::Borrowed("1")])]),
                false,
            ),
        ];
        for test in tests {
            let result = test.0.try_into();
            // let result = super::parse_query(test.0);
            if test.2 {
                let result = result.clone();
                assert_eq!(test.1, result.unwrap());
            }
            // println!("test: {:?}", test);
            if !test.2 {
                assert!(result.is_err())
            }
        }
    }

    #[test]
    fn test_encode() {
        let tests = vec![
            (
                Values::from_iter(vec![
                    (Cow::Borrowed("q"), vec![Cow::Borrowed("puppies")]),
                    (Cow::Borrowed("oe"), vec![Cow::Borrowed("utf8")]),
                ]),
                "oe=utf8&q=puppies",
            ),
            (
                Values::from_iter(vec![(
                    Cow::Borrowed("q"),
                    vec![
                        Cow::Borrowed("dogs"),
                        Cow::Borrowed("&"),
                        Cow::Borrowed("7"),
                    ],
                )]),
                "q=dogs&q=%26&q=7",
            ),
            (
                Values::from_iter(vec![
                    (
                        Cow::Borrowed("a"),
                        vec![
                            Cow::Borrowed("a1"),
                            Cow::Borrowed("a2"),
                            Cow::Borrowed("a3"),
                        ],
                    ),
                    (
                        Cow::Borrowed("b"),
                        vec![
                            Cow::Borrowed("b1"),
                            Cow::Borrowed("b2"),
                            Cow::Borrowed("b3"),
                        ],
                    ),
                    (
                        Cow::Borrowed("c"),
                        vec![
                            Cow::Borrowed("c1"),
                            Cow::Borrowed("c2"),
                            Cow::Borrowed("c3"),
                        ],
                    ),
                ]),
                "a=a1&a=a2&a=a3&b=b1&b=b2&b=b3&c=c1&c=c2&c=c3",
            ),
        ];

        for test in tests {
            let q = test.0.encode();
            assert_eq!(q, test.1.to_string());
        }
    }
}
