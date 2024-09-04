use kadena_lc_core::types::error::TypesError;
use kadena_lc_core::types::header::KadenaHeaderRaw;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct BlockHeaderResponse {
    next: String,
    items: Vec<String>,
    limit: usize,
}

impl TryInto<Vec<KadenaHeaderRaw>> for BlockHeaderResponse {
    type Error = TypesError;

    fn try_into(self) -> Result<Vec<KadenaHeaderRaw>, Self::Error> {
        self.items
            .into_iter()
            .map(|item| KadenaHeaderRaw::from_base64(&item.into_bytes()))
            .collect()
    }
}
