use std::{borrow::Cow, collections::HashMap, convert::TryFrom, iter::FromIterator, str::FromStr};

use crate::{errors::Error, query_unescape, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Value<'a> {
    inner: HashMap<Cow<'a, str>, Vec<Cow<'a, str>>>,
}

impl<'a> TryFrom<&'a str> for Value<'a> {
    type Error = Error;

    fn try_from(query: &'a str) -> Result<Self> {
        parse_query(query)
    }
}

impl<'a> FromIterator<(Cow<'a, str>, Vec<Cow<'a, str>>)> for Value<'a> {
    fn from_iter<T: IntoIterator<Item = (Cow<'a, str>, Vec<Cow<'a, str>>)>>(iter: T) -> Self {
        let inner = HashMap::from_iter(iter);
        Value { inner }
    }
}

fn parse_query<'a>(query: &'a str) -> Result<Value<'a>> {
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

    Ok(Value { inner })
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::convert::TryInto;
    use std::iter::FromIterator;

    use crate::query::Value;

    #[test]
    fn test() {
        let tests = vec![
            (
                "a=1",
                Value::from_iter(vec![(Cow::Borrowed("a"), vec![Cow::Borrowed("1")])]),
                true,
            ),
            (
                "a=1&b=2",
                Value::from_iter(vec![
                    (Cow::Borrowed("a"), vec![Cow::Borrowed("1")]),
                    (Cow::Borrowed("b"), vec![Cow::Borrowed("2")]),
                ]),
                true,
            ),
            (
                "a=1&a=2&a=banana",
                Value::from_iter(vec![(
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
                Value::from_iter(vec![(
                    Cow::Borrowed("ascii"),
                    vec![Cow::Borrowed("<key: 0x90>")],
                )]),
                true,
            ),
            ("a=1;b=2", Value::from_iter(vec![]), false),
            ("a;b=2", Value::from_iter(vec![]), false),
            (
                "a=%3B",
                Value::from_iter(vec![(Cow::Borrowed("a"), vec![Cow::Borrowed(";")])]),
                true,
            ),
            (
                "a%3Bb=1",
                Value::from_iter(vec![(Cow::Borrowed("a;b"), vec![Cow::Borrowed("1")])]),
                true,
            ),
            (
                "a=1&a=2;a=banana",
                Value::from_iter(vec![(Cow::Borrowed("a"), vec![Cow::Borrowed("1")])]),
                false,
            ),
            (
                "a;b&c=1",
                Value::from_iter(vec![(Cow::Borrowed("c"), vec![Cow::Borrowed("1")])]),
                false,
            ),
            (
                "a=1&b=2;a=3&c=4",
                Value::from_iter(vec![
                    (Cow::Borrowed("a"), vec![Cow::Borrowed("1")]),
                    (Cow::Borrowed("c"), vec![Cow::Borrowed("4")]),
                ]),
                false,
            ),
            (
                "a=1&b=2;c=3",
                Value::from_iter(vec![(Cow::Borrowed("a"), vec![Cow::Borrowed("1")])]),
                false,
            ),
            (";", Value::from_iter(vec![]), false),
            (
                "a=1&;",
                Value::from_iter(vec![(Cow::Borrowed("a"), vec![Cow::Borrowed("1")])]),
                false,
            ),
            (
                ";a=1&b=2",
                Value::from_iter(vec![(Cow::Borrowed("b"), vec![Cow::Borrowed("2")])]),
                false,
            ),
            (
                "a=1&b=2;",
                Value::from_iter(vec![(Cow::Borrowed("a"), vec![Cow::Borrowed("1")])]),
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
}
