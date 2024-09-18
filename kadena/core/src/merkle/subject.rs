use getset::Getters;

#[derive(Clone, Debug, Getters)]
#[getset(get = "pub")]
pub struct Subject {
    input: String,
}

impl Subject {
    pub fn new(input: String) -> Self {
        Self { input }
    }
}
