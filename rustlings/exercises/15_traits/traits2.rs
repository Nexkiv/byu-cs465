trait AppendBar {
    fn append_bar(self) -> Self;
}

// `append_bar` should push the string "Bar" into the vector.
impl AppendBar for Vec<String> {
    fn append_bar(self) -> Self {
        let suffix: String = "Bar".to_string();
        let mut new_vector = self.clone();
        new_vector.push(suffix);
        new_vector
    }
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_vec_pop_eq_bar() {
        let mut foo = vec![String::from("Foo")].append_bar();
        assert_eq!(foo.pop().unwrap(), "Bar");
        assert_eq!(foo.pop().unwrap(), "Foo");
    }
}
