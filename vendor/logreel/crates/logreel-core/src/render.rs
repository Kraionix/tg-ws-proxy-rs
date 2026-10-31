/// Text rendering implemented by the consumer.
///
/// The library writes the prefix: UTC timestamp, level, optional connection
/// id. The implementation writes the body only. Rendering runs on the writer
/// thread, never on the emit path.
pub trait Render {
    /// Append the body of the line, without a trailing newline.
    fn render(&self, out: &mut String);
}
