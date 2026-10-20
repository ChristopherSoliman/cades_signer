use std::iter::Peekable;

#[derive(Debug)]
pub enum ParserError {
    InvalidJson(char),
}

impl std::error::Error for ParserError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::fmt::Display for ParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParserError::InvalidJson(pos) => write!(f, "Invalid JSON format at pos: {}", pos),
        }
    }
}

pub struct CanonicalParser<I>
where
    I: Iterator<Item = char>,
{
    chars: Peekable<I>,
}

impl<I> CanonicalParser<I>
where
    I: Iterator<Item = char>,
{
    pub fn new(char: I) -> CanonicalParser<I> {
        CanonicalParser {
            chars: char.peekable(),
        }
    }

    pub fn parse(&mut self) -> Result<String, ParserError> {
        match self.parse_next(None) {
            Some(data) => Ok(data),
            None => Err(ParserError::InvalidJson(self.chars.next().unwrap())),
        }
    }

    fn next_including_spaces(&mut self) -> Option<char> {
        if let Some(c) = self.chars.next() {
            return Some(c);
        }
        None
    }

    fn next(&mut self) -> Option<char> {
        while let Some(c) = self.chars.next() {
            if !c.is_whitespace() {
                return Some(c);
            }
        }
        None
    }

    fn peek(&mut self) -> Option<char> {
        while let Some(c) = self.chars.peek() {
            if !c.is_whitespace() {
                return Some(*c);
            }
            self.chars.next().unwrap();
        }
        None
    }

    fn parse_object(&mut self) -> Option<String> {
        if self.next()? != '{' {
            return None;
        }

        if self.peek()? == '}' {
            self.next();
            return Some(String::from(""));
        }

        let mut obj = String::new();

        loop {
            let mut object_key = match self.peek()? {
                '"' => self.parse_next(None).unwrap(),
                _ => return None,
            };

            object_key.remove(0);
            object_key.remove(object_key.len() - 1);
            let colon = self.next();
            if colon != Some(':') {
                return None;
            }

            obj = format!(
                "{}\"{}\"{}",
                obj,
                object_key.to_uppercase(),
                self.parse_next(Some(&object_key))?
            );

            match self.next()? {
                ',' => {}
                '}' => return Some(obj),
                _ => return None,
            };
        }
    }

    fn parse_array(&mut self, current_key: Option<&String>) -> Option<String> {
        if self.next()? != '[' {
            return None;
        }

        if self.peek()? == ']' {
            self.next();
            return Some(String::from(""));
        }

        let mut array_str = format!(
            "\"{}\"{}",
            current_key.clone().unwrap().to_uppercase(),
            self.parse_next(current_key)?,
        );
        loop {
            match self.next()? {
                ',' => {
                    array_str = format!(
                        "{}\"{}\"{}",
                        array_str,
                        current_key.clone().unwrap().to_uppercase(),
                        self.parse_next(current_key)?,
                    );
                }
                ']' => return Some(array_str),
                _ => return None,
            }
        }
    }

    fn parse_string(&mut self) -> Option<String> {
        if self.next()? != '"' {
            return None;
        }

        let mut str = String::new();
        loop {
            let c = match self.next_including_spaces()? {
                '"' => return Some(format!("\"{str}\"")),
                c => c,
            };
            str.push(c);
        }
    }

    fn parse_keyword(&mut self, keyword: &str) -> bool {
        for c in keyword.chars() {
            if self.next_including_spaces() != Some(c) {
                return false;
            }
        }
        return true;
    }

    fn parse_null(&mut self) -> Option<String> {
        if self.parse_keyword("null") {
            return Some(String::from("\"null\""));
        } else {
            return None;
        }
    }

    fn parse_true(&mut self) -> Option<String> {
        if self.parse_keyword("true") {
            return Some(String::from("\"true\""));
        } else {
            return None;
        }
    }

    fn parse_false(&mut self) -> Option<String> {
        if self.parse_keyword("false") {
            return Some(String::from("\"false\""));
        } else {
            return None;
        }
    }

    fn parse_number(&mut self) -> Option<String> {
        let mut num = String::new();

        if let Some('-') = self.chars.peek() {
            self.next_including_spaces();
            num.push('-');
        };

        match self.next_including_spaces()? {
            '0' => num.push('0'),
            d @ '1'..='9' => {
                num.push(d);
                while let Some('0'..='9') = self.chars.peek() {
                    num.push(self.next_including_spaces().unwrap());
                }
            }
            _ => return None,
        }

        if let Some('.') = self.chars.peek() {
            num.push(self.next_including_spaces().unwrap());
            match self.next_including_spaces()? {
                d @ '0'..='9' => num.push(d),
                _ => return None,
            }

            while let Some('0'..='9') = self.chars.peek() {
                num.push(self.next_including_spaces().unwrap());
            }
        }

        if let Some('e' | 'E') = self.chars.peek() {
            num.push(self.next_including_spaces().unwrap());
            if let Some('-' | '+') = self.chars.peek() {
                num.push(self.next_including_spaces().unwrap());
            }

            match self.next_including_spaces()? {
                d @ '0'..='9' => num.push(d),
                _ => return None,
            }

            while let Some('0'..='9') = self.chars.peek() {
                num.push(self.next_including_spaces().unwrap());
            }
        }
        Some(format!("\"{}\"", num))
    }

    fn parse_next(&mut self, current_key: Option<&String>) -> Option<String> {
        match self.peek()? {
            '0'..='9' | '-' => self.parse_number(),
            '{' => self.parse_object(),
            '"' => self.parse_string(),
            '[' => self.parse_array(current_key),
            't' => self.parse_true(),
            'f' => self.parse_false(),
            'n' => self.parse_null(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::CanonicalParser;

    #[test]
    fn test_canonical() {
        let json = r#"{"obj1":"test", "obj2":["a", 1, 1.43, true, null, {"obj3":{"a":1,"b":2}}]}"#;
        let canonical = r#""OBJ1""test""OBJ2""OBJ2""a""OBJ2""1""OBJ2""1.43""OBJ2""true""OBJ2""null""OBJ2""OBJ3""A""1""B""2""#;

        let mut parser = CanonicalParser::new(json.chars().peekable());
        assert_eq!(parser.parse().unwrap(), canonical);
    }
}
