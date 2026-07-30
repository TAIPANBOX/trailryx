//! A Parquet writer, restricted on purpose.
//!
//! PLAIN encoding, no compression, one row group, data pages of version one.
//! No dictionaries, no statistics, no lists, no nesting. That subset is a few
//! hundred lines and produces files any Parquet reader opens; the rest of the
//! format is compression and speed, and neither is what stage 9 is for.
//!
//! # Why hand-written, and how it is checked
//!
//! Writing it keeps the zero-dependency property, and that would be a bad trade
//! if the result were only "Parquet-ish". So correctness is not argued here, it
//! is delegated: the test suite writes a file and has **pyarrow** read it back
//! and compare every value. An implementation checked against a reader written
//! by other people is checked in the way that matters, which is more than a
//! second implementation of our own would be.
//!
//! # Repeated fields
//!
//! Real Parquet lists, in the canonical three-level form:
//!
//! ```text
//! required group NAME (LIST) {
//!   repeated group list {
//!     required binary element (UTF8);
//!   }
//! }
//! ```
//!
//! They used to be comma-joined strings. That was lossless, because no
//! identifier's grammar admits a comma, and it was written down rather than
//! hidden. What it was not is **honest columnar output**: `pyarrow` handed back a
//! string where the record has a list, so anybody querying the export had to know
//! to split it, and `docs/planning/trailryx-plan.md` §6.3 makes lossless open
//! export an obligation rather than a nicety. A column that needs local knowledge
//! to read is a column that carries a trust debt.
//!
//! Both outer levels are chosen to keep the machinery small, and the choice is
//! the record's shape rather than convenience: a repeated record field is a
//! `Vec` that is always present and whose elements are validated tokens that are
//! never null. So the group is `required` and the element is `required`, which
//! makes the maximum definition level 1 and the maximum repetition level 1. One
//! bit each, and the existing run-length encoder covers both.
//!
//! The one case that needs care is the empty list: it writes a level pair with a
//! definition level of zero and **no value**, which is how Parquet distinguishes
//! "this row has an empty list" from "this row has one element". Getting it wrong
//! shifts every later row's values by one, and the test that catches it is a
//! round trip through `pyarrow` with an empty list in the middle.

use crate::thrift::{Kind, Writer as Thrift};

const MAGIC: &[u8; 4] = b"PAR1";

/// The physical types this writer emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    Int32,
    Int64,
    /// UTF-8, with the converted type set so a reader gives back a string
    /// rather than bytes.
    String,
}

impl ColumnType {
    fn physical(self) -> i32 {
        match self {
            Self::Int32 => 1,
            Self::Int64 => 2,
            Self::String => 6, // BYTE_ARRAY
        }
    }

    fn converted(self) -> Option<i32> {
        match self {
            Self::String => Some(0), // UTF8
            _ => None,
        }
    }
}

/// One column's values for the whole row group.
#[derive(Debug, Clone, PartialEq)]
pub enum Values {
    Int32(Vec<Option<i32>>),
    Int64(Vec<Option<i64>>),
    String(Vec<Option<String>>),
    /// One list of strings per row. The list is always present; an absent value
    /// is the empty list, which is what a `Vec` in a record can be and what it
    /// cannot be is null.
    StringList(Vec<Vec<String>>),
}

impl Values {
    fn len(&self) -> usize {
        match self {
            Self::Int32(v) => v.len(),
            Self::Int64(v) => v.len(),
            Self::String(v) => v.len(),
            Self::StringList(v) => v.len(),
        }
    }

    /// Whether this column is a Parquet list, which changes its schema shape,
    /// its levels and what `num_values` counts.
    fn is_list(&self) -> bool {
        matches!(self, Self::StringList(_))
    }

    /// The same question, public, because the oracle test has to tell the outside
    /// reader which columns it must hand back as lists. Without that the test
    /// compares rendered text and would pass whether the reader returned a list or
    /// a string, which is exactly the change being made here.
    pub fn is_list_column(&self) -> bool {
        self.is_list()
    }

    fn column_type(&self) -> ColumnType {
        match self {
            Self::Int32(_) => ColumnType::Int32,
            Self::Int64(_) => ColumnType::Int64,
            Self::String(_) => ColumnType::String,
            Self::StringList(_) => ColumnType::String,
        }
    }

    /// One cell, rendered for comparison. Not part of the format: it exists so
    /// a test can hand an outside reader our own idea of what the file holds
    /// and have every value checked rather than a few sampled ones.
    pub fn cell(&self, i: usize) -> Option<String> {
        match self {
            Self::Int32(v) => v.get(i).copied().flatten().map(|x| x.to_string()),
            Self::Int64(v) => v.get(i).copied().flatten().map(|x| x.to_string()),
            Self::String(v) => v.get(i).cloned().flatten(),
            // The comma-joined rendering, kept for the comparison path only. It
            // is no longer how the column is written, and the round-trip test
            // splits `pyarrow`'s list back to compare against it.
            Self::StringList(v) => v.get(i).map(|list| list.join(",")),
        }
    }

    pub fn count(&self) -> usize {
        self.len()
    }

    fn definition_levels(&self) -> Vec<bool> {
        match self {
            Self::Int32(v) => v.iter().map(Option::is_some).collect(),
            Self::Int64(v) => v.iter().map(Option::is_some).collect(),
            Self::String(v) => v.iter().map(Option::is_some).collect(),
            // An empty list is one level entry at zero and no value; a list of n
            // elements is n entries at one. This is the encoding, so it is written
            // out here rather than derived at the call site.
            Self::StringList(v) => v
                .iter()
                .flat_map(|list| {
                    if list.is_empty() {
                        vec![false]
                    } else {
                        vec![true; list.len()]
                    }
                })
                .collect(),
        }
    }

    /// Repetition levels: zero starts a new list, one continues the current one.
    ///
    /// Empty only for a column that is not a list, where Parquet omits the
    /// repetition levels from the page entirely.
    fn repetition_levels(&self) -> Vec<bool> {
        match self {
            Self::StringList(v) => v
                .iter()
                .flat_map(|list| {
                    let count = list.len().max(1);
                    (0..count).map(|i| i > 0)
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// How many level entries the page carries.
    ///
    /// For a list this is **not** the row count: an empty list contributes one
    /// entry and a three-element list contributes three. Writing the row count
    /// here instead makes a reader stop early or run off the end, and the failure
    /// looks like a corrupt file rather than like a wrong number.
    fn level_count(&self) -> usize {
        match self {
            Self::StringList(v) => v.iter().map(|list| list.len().max(1)).sum(),
            _ => self.len(),
        }
    }

    /// PLAIN, little-endian, nulls contributing nothing.
    fn plain(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Int32(v) => {
                for value in v.iter().flatten() {
                    out.extend_from_slice(&value.to_le_bytes());
                }
            }
            Self::StringList(v) => {
                for value in v.iter().flatten() {
                    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
                    out.extend_from_slice(value.as_bytes());
                }
            }
            Self::Int64(v) => {
                for value in v.iter().flatten() {
                    out.extend_from_slice(&value.to_le_bytes());
                }
            }
            Self::String(v) => {
                for value in v.iter().flatten() {
                    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
                    out.extend_from_slice(value.as_bytes());
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Column {
    pub name: String,
    /// Whether a null may appear. A required column with a null in it is a
    /// programming error rather than a data condition, so it is caught here.
    pub optional: bool,
    pub values: Values,
}

impl Column {
    pub fn required(name: &str, values: Values) -> Self {
        Self {
            name: name.to_owned(),
            optional: false,
            values,
        }
    }

    pub fn optional(name: &str, values: Values) -> Self {
        Self {
            name: name.to_owned(),
            optional: true,
            values,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteError {
    /// Columns of different lengths cannot be rows.
    RaggedColumns,
    /// A null in a column declared required.
    NullInRequired,
    NoColumns,
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RaggedColumns => write!(f, "columns have different lengths"),
            Self::NullInRequired => write!(f, "a required column holds a null"),
            Self::NoColumns => write!(f, "a file needs at least one column"),
        }
    }
}

impl std::error::Error for WriteError {}

/// Run-length encode a run of booleans as Parquet's hybrid encoding.
///
/// Only RLE runs, never bit-packed ones. Both are legal and a reader takes
/// either; emitting one kind keeps this function short enough to check by eye.
fn rle_levels(levels: &[bool]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < levels.len() {
        let value = levels[i];
        let mut run = 1;
        while i + run < levels.len() && levels[i + run] == value {
            run += 1;
        }
        // Header: run length shifted left by one, low bit zero for an RLE run.
        let mut header = (run as u64) << 1;
        loop {
            let byte = (header & 0x7f) as u8;
            header >>= 7;
            if header == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        // The value itself, in ceil(bit_width / 8) bytes, and the bit width for
        // a maximum definition level of one is one bit.
        out.push(u8::from(value));
        i += run;
    }
    out
}

/// Write one row group holding every column.
pub fn write(columns: &[Column]) -> Result<Vec<u8>, WriteError> {
    let Some(first) = columns.first() else {
        return Err(WriteError::NoColumns);
    };
    let rows = first.values.len();
    for column in columns {
        if column.values.len() != rows {
            return Err(WriteError::RaggedColumns);
        }
        // A list's zero definition levels mean "this row's list is empty", not
        // "this row is null", so the requiredness check does not apply to one.
        if !column.optional
            && !column.values.is_list()
            && column.values.definition_levels().iter().any(|d| !d)
        {
            return Err(WriteError::NullInRequired);
        }
    }

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);

    // Column chunks, one page each, in schema order.
    let mut chunks = Vec::with_capacity(columns.len());
    for column in columns {
        let offset = out.len() as i64;
        let mut page = Vec::new();
        // Data page v1 puts the levels inside the page, each prefixed with its
        // byte length, and repetition comes before definition. That order is the
        // specification's and getting it the other way round produces a file that
        // parses and reads nonsense.
        let repetition = column.values.repetition_levels();
        if !repetition.is_empty() {
            let levels = rle_levels(&repetition);
            page.extend_from_slice(&(levels.len() as u32).to_le_bytes());
            page.extend_from_slice(&levels);
        }
        if column.optional || column.values.is_list() {
            let levels = rle_levels(&column.values.definition_levels());
            page.extend_from_slice(&(levels.len() as u32).to_le_bytes());
            page.extend_from_slice(&levels);
        }
        page.extend_from_slice(&column.values.plain());

        let header = page_header(column.values.level_count(), page.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&page);

        chunks.push(ChunkMeta {
            name: column.name.clone(),
            column_type: column.values.column_type(),
            is_list: column.values.is_list(),
            num_values: column.values.level_count() as i64,
            size: (header.len() + page.len()) as i64,
            data_page_offset: offset,
        });
    }

    let total_size: i64 = chunks.iter().map(|c| c.size).sum();
    let footer = file_metadata(columns, &chunks, rows as i64, total_size);
    out.extend_from_slice(&footer);
    out.extend_from_slice(&(footer.len() as u32).to_le_bytes());
    out.extend_from_slice(MAGIC);
    Ok(out)
}

struct ChunkMeta {
    name: String,
    column_type: ColumnType,
    /// A list's leaf is three levels down, so its `path_in_schema` is three names
    /// rather than one. A reader that is handed the wrong path cannot find the
    /// column at all.
    is_list: bool,
    num_values: i64,
    size: i64,
    data_page_offset: i64,
}

/// FieldRepetitionType.
const REQUIRED: i32 = 0;
const OPTIONAL: i32 = 1;
const REPEATED: i32 = 2;

/// ConvertedType::LIST.
const CONVERTED_LIST: i32 = 3;

/// One entry of the flattened schema.
struct SchemaElement<'a> {
    /// `None` for a group, which has no physical type.
    physical: Option<i32>,
    repetition: i32,
    name: &'a str,
    /// `None` for a leaf.
    children: Option<i32>,
    converted: Option<i32>,
}

/// The schema, flattened in the pre-order a Parquet footer wants.
fn schema_elements(columns: &[Column]) -> Vec<SchemaElement<'_>> {
    let mut out = Vec::with_capacity(columns.len() * 3 + 1);
    out.push(SchemaElement {
        physical: None,
        // The root carries no repetition type in practice, and writers emit
        // REQUIRED. `children` counts top-level columns, never the leaves buried
        // inside a list: a count that included them would make the reader read
        // a list's inner groups as further top-level columns.
        repetition: REQUIRED,
        name: "trailryx_record",
        children: Some(columns.len() as i32),
        converted: None,
    });
    for column in columns {
        let kind = column.values.column_type();
        if column.values.is_list() {
            out.push(SchemaElement {
                physical: None,
                repetition: REQUIRED,
                name: &column.name,
                children: Some(1),
                converted: Some(CONVERTED_LIST),
            });
            out.push(SchemaElement {
                physical: None,
                repetition: REPEATED,
                // The names are the specification's, not ours. A reader looking
                // for the canonical three-level form matches on them.
                name: "list",
                children: Some(1),
                converted: None,
            });
            out.push(SchemaElement {
                physical: Some(kind.physical()),
                repetition: REQUIRED,
                name: "element",
                children: None,
                converted: kind.converted(),
            });
        } else {
            out.push(SchemaElement {
                physical: Some(kind.physical()),
                repetition: if column.optional { OPTIONAL } else { REQUIRED },
                name: &column.name,
                children: None,
                converted: kind.converted(),
            });
        }
    }
    out
}

fn page_header(num_values: usize, page_size: usize) -> Vec<u8> {
    let mut t = Thrift::new();
    t.i32_field(1, 0); // PageType::DATA_PAGE
    t.i32_field(2, page_size as i32); // uncompressed
    t.i32_field(3, page_size as i32); // compressed: the same, nothing is compressed
    t.struct_field(5, |t| {
        t.i32_field(1, num_values as i32);
        t.i32_field(2, 0); // Encoding::PLAIN
        t.i32_field(3, 3); // definition levels: Encoding::RLE
        t.i32_field(4, 3); // repetition levels: Encoding::RLE
    });
    t.end_struct();
    t.into_bytes()
}

fn file_metadata(columns: &[Column], chunks: &[ChunkMeta], rows: i64, total: i64) -> Vec<u8> {
    let mut t = Thrift::new();
    t.i32_field(1, 1); // format version

    // The schema is a flat pre-order walk of a tree, and the reader rebuilds the
    // tree from each element's child count. A flat column is one element; a list
    // is three, because the canonical form wraps the leaf in a LIST group and a
    // repeated group. Flattened here rather than emitted inline so the total count
    // and the walk cannot disagree.
    let schema = schema_elements(columns);
    t.list_field(2, Kind::Struct, schema.len(), |t, i| {
        let element = &schema[i];
        t.elem_struct(|t| {
            if let Some(physical) = element.physical {
                t.i32_field(1, physical);
            }
            t.i32_field(3, element.repetition);
            t.string_field(4, element.name);
            if let Some(children) = element.children {
                t.i32_field(5, children);
            }
            if let Some(converted) = element.converted {
                t.i32_field(6, converted);
            }
        });
    });

    t.i64_field(3, rows);

    t.list_field(4, Kind::Struct, 1, |t, _| {
        t.elem_struct(|t| {
            t.list_field(1, Kind::Struct, chunks.len(), |t, i| {
                let chunk = &chunks[i];
                t.elem_struct(|t| {
                    t.i64_field(2, chunk.data_page_offset); // file_offset
                    t.struct_field(3, |t| {
                        t.i32_field(1, chunk.column_type.physical());
                        t.list_field(2, Kind::I32, 1, |t, _| t.elem_i32(0)); // PLAIN
                        // path_in_schema: one name for a flat column, three for
                        // a list leaf.
                        if chunk.is_list {
                            t.list_field(3, Kind::Binary, 3, |t, part| {
                                t.elem_string(match part {
                                    0 => chunk.name.as_str(),
                                    1 => "list",
                                    _ => "element",
                                })
                            });
                        } else {
                            t.list_field(3, Kind::Binary, 1, |t, _| t.elem_string(&chunk.name));
                        }
                        t.i32_field(4, 0); // CompressionCodec::UNCOMPRESSED
                        t.i64_field(5, chunk.num_values);
                        t.i64_field(6, chunk.size);
                        t.i64_field(7, chunk.size);
                        t.i64_field(9, chunk.data_page_offset);
                    });
                });
            });
            t.i64_field(2, total);
            t.i64_field(3, rows);
        });
    });

    t.string_field(6, "trailryx");
    t.end_struct();
    t.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Column> {
        vec![
            Column::required("n", Values::Int64(vec![Some(1), Some(2), Some(3)])),
            Column::optional(
                "s",
                Values::String(vec![Some("a".into()), None, Some("c".into())]),
            ),
        ]
    }

    #[test]
    fn a_file_has_the_shape_a_reader_looks_for() {
        let bytes = write(&sample()).unwrap();
        assert_eq!(&bytes[..4], MAGIC);
        assert_eq!(&bytes[bytes.len() - 4..], MAGIC);
        let len_at = bytes.len() - 8;
        let mut len = [0u8; 4];
        len.copy_from_slice(&bytes[len_at..len_at + 4]);
        let len = u32::from_le_bytes(len) as usize;
        assert!(len > 0 && len < bytes.len(), "footer length {len}");
    }

    #[test]
    fn ragged_columns_are_refused() {
        let columns = vec![
            Column::required("a", Values::Int64(vec![Some(1)])),
            Column::required("b", Values::Int64(vec![Some(1), Some(2)])),
        ];
        assert_eq!(write(&columns), Err(WriteError::RaggedColumns));
    }

    #[test]
    fn a_null_in_a_required_column_is_refused() {
        let columns = vec![Column::required("a", Values::Int64(vec![None]))];
        assert_eq!(write(&columns), Err(WriteError::NullInRequired));
    }

    #[test]
    fn definition_levels_run_length_encode() {
        // Three present, two absent, one present.
        let levels = [true, true, true, false, false, true];
        assert_eq!(rle_levels(&levels), vec![6, 1, 4, 0, 2, 1]);
    }

    #[test]
    fn the_same_rows_always_produce_the_same_bytes() {
        // A projection has to be rebuildable byte for byte, and that starts
        // here: nothing in the writer may depend on iteration order or a clock.
        assert_eq!(write(&sample()).unwrap(), write(&sample()).unwrap());
    }
}
