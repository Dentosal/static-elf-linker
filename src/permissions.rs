#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Permissions {
    pub fn relax(&mut self, other: Self) {
        self.read |= other.read;
        self.write |= other.write;
        self.execute |= other.execute;
    }

    #[allow(dead_code)]
    pub fn restrict(&mut self, other: Self) {
        self.read &= other.read;
        self.write &= other.write;
        self.execute &= other.execute;
    }
}
