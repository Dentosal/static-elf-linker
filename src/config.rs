#[derive(Debug, Clone)]
pub struct Config {
    /// Where the program should be loaded
    pub base_addr: u64,
    /// Alignment of segments in the file
    pub segment_file_align: u64,
    /// Alignment of diffrently-permissioned segments in memory
    pub page_size: u64,
}
