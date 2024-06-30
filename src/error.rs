use derive_more::From;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(From)]
pub enum Error {
    #[from]
    Custom(String),
}
