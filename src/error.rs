use std::fmt;

#[derive(Debug)]
pub enum LuminationError {
    Net,
    Procs,
}

impl std::error::Error for LuminationError {}

impl fmt::Display for LuminationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LuminationError::Net => write!(f, "Could not parse net connections"),
            LuminationError::Procs => write!(f, "Could not parse Processes connections"),
        }
    }
}
