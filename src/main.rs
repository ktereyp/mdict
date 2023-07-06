extern crate core;

use std::{fs, io, process};
use std::env::args;
use std::fmt::{Debug, Display, Formatter};
use std::mem::size_of;
use std::io::{Read, Write, Seek, SeekFrom, Cursor, BufRead};
use std::path::Path;
use log::{debug, info, warn};
use adler32;
use serde::{Deserialize};
use serde_xml_rs::{from_str};
use flate2::read::ZlibDecoder;
use crate::Encoding::Utf16;
use base64;
use base64::Engine;

struct Error {
    msg: String,
}

impl From<String> for Error {
    fn from(msg: String) -> Self {
        Error {
            msg,
        }
    }
}

impl From<&str> for Error {
    fn from(msg: &str) -> Self {
        Error {
            msg: msg.to_string(),
        }
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.msg, f)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.msg, f)
    }
}

#[allow(dead_code)]
enum ByteOrder {
    LE,
    BE,
}

macro_rules! read_integer {
    (ByteOrder::LE, $x: ty, $r: expr) => {
        {
            const LENGTH: usize = size_of::<$x>();
            let mut buff: [u8; LENGTH] = [0; LENGTH];
            $r.read(&mut buff).expect("cannot read");
            <$x>::from_le_bytes(buff)
        }
    };
    (ByteOrder::BE, $x: ty, $r: expr) => {
        {
            const LENGTH: usize = size_of::<$x>();
            let mut buff: [u8; LENGTH] = [0; LENGTH];
            $r.read(&mut buff).expect("cannot read");
            <$x>::from_be_bytes(buff)
        }
    };
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct DictHeader {
    generated_by_engine_version: String,
    required_engine_version: String,
    encrypted: i32,
    encoding: String,
    format: String,
    #[serde(default)]
    creation_date: String,
    #[serde(default)]
    compact: String,
    #[serde(default)]
    compat: String,
    #[serde(default)]
    key_case_sensitive: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    data_source_format: String,
    #[serde(default)]
    style_sheet: String,
    #[serde(default)]
    register_by: String,
    #[serde(default)]
    reg_code: String,
}

#[allow(dead_code)]
#[derive(Default, Debug)]
struct KeyIndexSection {
    offset: i64,
    key_block_data_offset: i64,
    num_blocks: i64,
    num_entries: i64,
    key_info_decompressed_data_len: i64,
    key_block_info_bytes_len: i64,
    key_block_data_len: i64,
    index: Vec<KeyBlockInfo>,
    entries: Vec<Entry>,
}

#[derive(Default, Debug)]
struct Entry {
    record_offset: i64,
    data_size: i64,
    key: String,
}

#[derive(Default, Debug)]
struct KeyBlockInfo {
    number_of_entries: i64,
    first: String,
    last: String,
    compressed_size: i64,
    decompressed_size: i64,
}

#[derive(Default, Debug)]
struct RecordBlockIndex {
    compressed_size: i64,
    decompressed_size: i64,
}

#[derive(Default, Debug)]
struct RecordBlockSection {
    offset: i64,
    record_block_offset: i64,
    number_of_record_block: i64,
    number_of_entries: i64,
    record_index_data_size: i64,
    record_block_data_size: i64,
    index: Vec<RecordBlockIndex>,
}

#[derive(PartialEq)]
enum DictFormatVersion {
    V1,
    V2,
}

impl DictFormatVersion {
    fn from(s: &str) -> Option<DictFormatVersion> {
        let pos = s.find(".")?;
        match &s[0..pos] {
            "1" => Some(DictFormatVersion::V1),
            "2" => Some(DictFormatVersion::V2),
            _ => None,
        }
    }
}

#[allow(dead_code)]
#[derive(PartialEq)]
enum Encoding {
    Utf8,
    Utf16,
}

impl Encoding {
    fn from(s: &str) -> Option<Encoding> {
        match s.to_lowercase().as_str() {
            "utf-8" | "utf8" => Some(Encoding::Utf8),
            "" | "utf-16" | "utf16" => Some(Utf16),
            _ => None,
        }
    }
}

#[allow(dead_code)]
struct MdxFile {
    file: fs::File,
    dict_header: DictHeader,
    ver: DictFormatVersion,
    encoding: Encoding,
    key_index_section: KeyIndexSection,
    record_block_sect: RecordBlockSection,
    entries: Vec<Entry>,
}

impl MdxFile {
    fn parse<P: AsRef<Path>>(file: P) -> Result<MdxFile, Error> {
        let mut f = fs::File::open(file).map_err(|e| e.to_string())?;
        let header_len = read_integer!(ByteOrder::BE, i32, f) as i64;
        let (header_content, check_sum) = {
            let mut header_content_bytes: Vec<u8> = vec![0; header_len as usize];
            f.read_exact(&mut header_content_bytes).map_err(|e| e.to_string())?;
            let adler = adler32::RollingAdler32::from_buffer(&header_content_bytes);
            let header_content_u16 = unsafe {
                std::slice::from_raw_parts_mut(header_content_bytes.as_mut_ptr().cast::<u16>(), header_content_bytes.len() / 2)
            };
            (String::from_utf16_lossy(header_content_u16), adler.hash())
        };
        let exp_check_sum = read_integer!(ByteOrder::LE, u32, f);
        if exp_check_sum != check_sum {
            return Err("header checksum does not match".into());
        }
        let dict_header: DictHeader = from_str(&header_content).unwrap();
        let version = DictFormatVersion::from(&dict_header.required_engine_version)
            .ok_or(Error::from("invalid required_engine_version"))?;

        let encoding = Encoding::from(&dict_header.encoding)
            .ok_or(Error::from("unsupported encoding"))?;

        let key_index_offset = 4 + header_len + 4;

        let mut key_index_section = KeyIndexSection::default();
        key_index_section.offset = key_index_offset as i64;
        if version == DictFormatVersion::V1 {
            let mut buff = vec![0; 4 * 4];
            f.read_exact(&mut buff).map_err(|e| e.to_string())?;
            key_index_section.num_blocks = i32::from_be_bytes(buff[0..4].try_into().unwrap()) as i64;
            key_index_section.num_entries = i32::from_be_bytes(buff[4..8].try_into().unwrap()) as i64;
            key_index_section.key_block_info_bytes_len = i32::from_be_bytes(buff[8..12].try_into().unwrap()) as i64;
            key_index_section.key_block_data_len = i32::from_be_bytes(buff[12..16].try_into().unwrap()) as i64;
            key_index_section.key_block_data_offset = key_index_section.offset
                + 4 * 4
                + key_index_section.key_block_info_bytes_len;
        } else if version == DictFormatVersion::V2 {
            let mut buff = vec![0; 5 * 8];
            f.read_exact(&mut buff).map_err(|e| e.to_string())?;
            key_index_section.num_blocks = i64::from_be_bytes(buff[0..8].try_into().unwrap());
            key_index_section.num_entries = i64::from_be_bytes(buff[8..16].try_into().unwrap());
            key_index_section.key_info_decompressed_data_len = i64::from_be_bytes(buff[16..24].try_into().unwrap());
            key_index_section.key_block_info_bytes_len = i64::from_be_bytes(buff[24..32].try_into().unwrap());
            key_index_section.key_block_data_len = i64::from_be_bytes(buff[32..40].try_into().unwrap());

            let expect_checksum = read_integer!(ByteOrder::BE, u32, f);
            if expect_checksum != adler32::RollingAdler32::from_buffer(&buff).hash() {
                return Err("layout checksum not match".into());
            }

            key_index_section.key_block_data_offset = key_index_section.offset
                + 5 * 8
                + 4
                + key_index_section.key_block_info_bytes_len;
        }

        let mut reader: Option<Box<dyn Read>> = None;
        if version == DictFormatVersion::V1 {
            reader = Some(Box::new(&f));
        } else if version == DictFormatVersion::V2 {
            let flag = read_integer!(ByteOrder::LE, i32, f);
            assert_eq!(flag, 2);
            let checksum = read_integer!(ByteOrder::BE, u32, f);

            let buff_len = (key_index_section.key_block_info_bytes_len - 8) as usize;
            let mut data = vec![0; buff_len];
            f.read_exact(&mut data).expect("cannot read data");

            if dict_header.encrypted & 2 > 0 {
                decrypt(&mut data, checksum);
            }

            let mut de = ZlibDecoder::new(data.as_slice());
            let mut decompressed_buff: Vec<u8> = vec![];
            de.read_to_end(&mut decompressed_buff).expect("decompress fail");

            reader = Some(Box::new(Cursor::new(decompressed_buff)));
        }
        let mut reader = reader.ok_or(Error::from("unsupport version"))?;

        // load key index
        for _ in 0..key_index_section.num_blocks {
            let mut key_block_info = KeyBlockInfo::default();
            if version == DictFormatVersion::V1 {
                key_block_info.number_of_entries = read_integer!(ByteOrder::BE, i32, reader) as i64;
                let first_len = read_integer!(ByteOrder::BE, i8, reader);
                let mut first_content: Vec<u8> = vec![0; first_len as usize];
                reader.read_exact(&mut first_content).map_err(|e| e.to_string())?;
                key_block_info.first = String::from_utf8_lossy(&first_content).to_string();

                let last_len = read_integer!(ByteOrder::BE, i8, reader);
                let mut last_content: Vec<u8> = vec![0; last_len as usize];
                reader.read_exact(&mut last_content).map_err(|e| e.to_string())?;
                key_block_info.last = String::from_utf8_lossy(&last_content).to_string();

                key_block_info.compressed_size = read_integer!(ByteOrder::BE, i32, reader) as i64;
                key_block_info.decompressed_size = read_integer!(ByteOrder::BE, i32, reader) as i64;

                key_index_section.index.push(key_block_info);
            } else if version == DictFormatVersion::V2 {
                key_block_info.number_of_entries = read_integer!(ByteOrder::BE, i64, reader);
                let mut read_str = || -> Result<String, Error>  {
                    if encoding == Encoding::Utf8 {
                        let l = read_integer!(ByteOrder::BE, i16, reader) + 1;
                        let mut first_content: Vec<u8> = vec![0; l as usize];
                        reader.read_exact(&mut first_content).map_err(|e| e.to_string())?;
                        Ok(String::from_utf8_lossy(&first_content[..first_content.len() - 1]).to_string())
                    } else if encoding == Encoding::Utf16 {
                        let l = ((read_integer!(ByteOrder::BE, i16, reader) + 1) as usize) * 2;
                        let mut buff: Vec<u8> = vec![0; l];
                        reader.read_exact(&mut buff).map_err(|e| e.to_string())?;
                        buff.pop();
                        buff.pop();
                        let buff = unsafe {
                            std::slice::from_raw_parts_mut(buff.as_mut_ptr().cast::<u16>(), buff.len() / 2)
                        };
                        Ok(String::from_utf16_lossy(&buff))
                    } else {
                        Ok(String::new())
                    }
                };
                key_block_info.first = read_str()?;
                key_block_info.last = read_str()?;
                key_block_info.compressed_size = read_integer!(ByteOrder::BE, i64, reader);
                key_block_info.decompressed_size = read_integer!(ByteOrder::BE, i64, reader);
                key_index_section.index.push(key_block_info);
            }
        }

        drop(reader);

        // load key block index
        let mut record_block_sect = RecordBlockSection::default();
        {
            if version == DictFormatVersion::V1 {
                record_block_sect.offset = key_index_offset +
                    4 * 4 +
                    key_index_section.key_block_info_bytes_len +
                    key_index_section.key_block_data_len;
            } else if version == DictFormatVersion::V2 {
                record_block_sect.offset = key_index_offset +
                    44 +
                    key_index_section.key_block_info_bytes_len +
                    key_index_section.key_block_data_len;
            } else {
                return Err("unsupported version".into());
            }
            f.seek(SeekFrom::Start(record_block_sect.offset as u64)).map_err(|e| e.to_string())?;
            {
                if version == DictFormatVersion::V1 {
                    record_block_sect.number_of_record_block = read_integer!(ByteOrder::BE, i32, f) as i64;
                    record_block_sect.number_of_entries = read_integer!(ByteOrder::BE, i32, f) as i64;
                    record_block_sect.record_index_data_size = read_integer!(ByteOrder::BE, i32, f) as i64;
                    record_block_sect.record_block_data_size = read_integer!(ByteOrder::BE, i32, f) as i64;
                    record_block_sect.record_block_offset = record_block_sect.offset
                        + 4 * 4 // four i32 length
                        + record_block_sect.record_index_data_size;
                } else {
                    record_block_sect.number_of_record_block = read_integer!(ByteOrder::BE, i64, f);
                    record_block_sect.number_of_entries = read_integer!(ByteOrder::BE, i64, f);
                    record_block_sect.record_index_data_size = read_integer!(ByteOrder::BE, i64, f);
                    record_block_sect.record_block_data_size = read_integer!(ByteOrder::BE, i64, f);
                    record_block_sect.record_block_offset = record_block_sect.offset
                        + 4 * 8 // four i32 length
                        + record_block_sect.record_index_data_size;
                }

                for _ in 0..record_block_sect.number_of_record_block {
                    if version == DictFormatVersion::V1 {
                        let cz = read_integer!(ByteOrder::BE, i32, f) as i64;
                        let dz = read_integer!(ByteOrder::BE, i32, f) as i64;
                        record_block_sect.index.push(RecordBlockIndex {
                            compressed_size: cz,
                            decompressed_size: dz,
                        });
                    } else {
                        let cz = read_integer!(ByteOrder::BE, i64, f);
                        let dz = read_integer!(ByteOrder::BE, i64, f);
                        record_block_sect.index.push(RecordBlockIndex {
                            compressed_size: cz,
                            decompressed_size: dz,
                        });
                    }
                }
            }
        }
        Ok(MdxFile {
            file: f,
            dict_header,
            ver: version,
            encoding,
            key_index_section,
            record_block_sect,
            entries: vec![],
        })
    }

    fn load_entries(&mut self) -> Result<(), Error> {
        // find index
        let mut key_block_offset = 0;
        for idx in &self.key_index_section.index {
            let offset = key_block_offset + self.key_index_section.key_block_data_offset;
            self.file.seek(SeekFrom::Start(offset as u64)).expect("cannot seek");
            let flag = read_integer!(ByteOrder::LE, i32, self.file);
            if flag != 2 {
                warn!("not zlib compress");
                return Err(Error::from("not zlib compress"));
            }
            let expect_adler32_checksum = read_integer!(ByteOrder::BE, u32, self.file);

            let block_buff_size = idx.compressed_size - 4 /*compress type*/ - 4 /* checksum*/;
            let mut block_buff: Vec<u8> = vec![0; block_buff_size as usize];
            self.file.read_exact(&mut block_buff).expect("cannot read");

            let mut de = ZlibDecoder::new(block_buff.as_slice());
            let mut decompressed_buff: Vec<u8> = vec![];
            de.read_to_end(&mut decompressed_buff).expect("decompress fail");

            let compute_adler32 = adler32::RollingAdler32::from_buffer(&decompressed_buff).hash();
            if compute_adler32 != expect_adler32_checksum {
                eprintln!("checksum does not match");
                return Err(Error::from("checksum does not match"));
            }

            let mut pos = 0;
            while pos < decompressed_buff.len() {
                if pos + 8 > decompressed_buff.len() {
                    break;
                }

                let record_offset = {
                    if self.ver == DictFormatVersion::V1 {
                        let mut buf: [u8; 4] = [0; 4];
                        buf.clone_from_slice(&decompressed_buff[pos..pos + 4]);
                        pos += 4;
                        i32::from_be_bytes(buf) as i64
                    } else {
                        let mut buf: [u8; 8] = [0; 8];
                        buf.clone_from_slice(&decompressed_buff[pos..pos + 8]);
                        pos += 8;
                        i64::from_be_bytes(buf)
                    }
                };
                let key_text_pos_start = pos;
                while let Some(&b) = decompressed_buff.get(pos) {
                    if self.encoding == Utf16 {
                        pos += 1;
                        if let Some(&b1) = decompressed_buff.get(pos) {
                            if b == 0 && b1 == 0 {
                                break;
                            }
                        } else {
                            break;
                        }
                    } else if b == 0 {
                        break;
                    }
                    pos += 1;
                }

                let key_buff = &decompressed_buff[key_text_pos_start..pos];
                let item = if self.encoding == Encoding::Utf16 {
                    let mut buff = key_buff.to_owned();
                    let utf16_buff = unsafe {
                        std::slice::from_raw_parts_mut(buff.as_mut_ptr().cast::<u16>(), buff.len() / 2)
                    };
                    String::from_utf16_lossy(utf16_buff)
                } else {
                    String::from_utf8_lossy(key_buff).to_string()
                };
                pos += 1;

                // try read next record_offset;
                let next_record_offset = {
                    if self.ver == DictFormatVersion::V1 {
                        if pos + 4 < decompressed_buff.len() {
                            let mut buf: [u8; 4] = [0; 4];
                            buf.clone_from_slice(&decompressed_buff[pos..pos + 4]);
                            i32::from_be_bytes(buf) as i64
                        } else {
                            0
                        }
                    } else {
                        if pos + 8 < decompressed_buff.len() {
                            let mut buf: [u8; 8] = [0; 8];
                            buf.clone_from_slice(&decompressed_buff[pos..pos + 8]);
                            i64::from_be_bytes(buf)
                        } else {
                            0
                        }
                    }
                };
                let data_size = if next_record_offset > record_offset {
                    next_record_offset - record_offset
                } else {
                    0
                };
                self.entries.push(Entry {
                    record_offset,
                    data_size,
                    key: item,
                })
            }

            key_block_offset += idx.compressed_size;
        }
        info!("entry count: {}", self.entries.len());
        return Ok(());
    }

    fn find(&mut self, key: String, case_sensitive: bool) -> Option<Record> {
        let entry = self.entries.iter().find(|k|
            match case_sensitive {
                true => k.key.eq(&key),
                false => k.key.eq_ignore_ascii_case(&key),
            }
        );
        if let Some(entry) = entry {
            // find block
            // read the  record block
            let mut block_offset = 0;
            let mut record_offset = 0;
            let record_block_index = self.record_block_sect.index.iter().find(|k| {
                let b = record_offset + k.decompressed_size > entry.record_offset;
                if !b {
                    record_offset += k.decompressed_size;
                    block_offset += k.compressed_size;
                }
                b
            });
            if record_block_index.is_none() {
                return None;
            }
            let record_block_index = record_block_index.unwrap();

            let block_offset = self.record_block_sect.record_block_offset + block_offset;
            self.file.seek(SeekFrom::Start(block_offset as u64)).expect("cannot seek");
            let flag = read_integer!(ByteOrder::LE, u32, self.file);
            // zip
            let expect_adler32_checksum = read_integer!(ByteOrder::BE, u32, self.file);
            let block_buff_size = record_block_index.compressed_size - 4/*flag*/ - 4/*checksum*/;
            let mut block_buff: Vec<u8> = vec![0; block_buff_size as usize];
            self.file.read_exact(&mut block_buff).expect("cannot read");

            if flag == 2 {
                let mut de = ZlibDecoder::new(block_buff.as_slice());
                let mut decompressed_buff: Vec<u8> = vec![];
                de.read_to_end(&mut decompressed_buff).expect("decompress fail");
                block_buff = decompressed_buff
            }

            let compute_adler32 = adler32::RollingAdler32::from_buffer(&block_buff).hash();
            if compute_adler32 != expect_adler32_checksum {
                eprintln!("checksum does not match")
            }

            let relative_offset = (entry.record_offset - record_offset) as usize;
            let data = if entry.data_size > 0 {
                Vec::from(&block_buff[relative_offset..relative_offset + entry.data_size as usize])
            } else {
                Vec::from(&block_buff[relative_offset..])
            };
            return Some(Record {
                key,
                data,
            });
        } else {
            return None;
        }

        //let mut key = key;
        //if self.dict_header.key_case_sensitive.to_lowercase() == "no" && key.contains(".") {
        //    key = key.to_lowercase();
        //}
        //let mut key_block_offset = 0;
        //let key_block_info = self.key_index_section.index.iter().find(|k| {
        //    let b = k.first <= key && k.last >= key;
        //    if !b {
        //        key_block_offset += k.compressed_size
        //    }
        //    b
        //});
        //if key_block_info.is_none() {
        //    return None;
        //}
        //let key_block_info = key_block_info.unwrap();

        //// read key block
        //let mut entry = None;
        //{
        //    let key_block_offset = key_block_offset + self.key_index_section.key_block_data_offset;
        //    self.file.seek(SeekFrom::Start(key_block_offset as u64)).expect("cannot seek");
        //    let flag = read_integer!(ByteOrder::LE, i32, self.file);
        //    if flag != 2 {
        //        warn!("not zlib compress");
        //        return None;
        //    }
        //    let expect_adler32_checksum = read_integer!(ByteOrder::BE, u32, self.file);

        //    let block_buff_size = key_block_info.compressed_size - 4 /*compress type*/ - 4 /* checksum*/;
        //    let mut block_buff: Vec<u8> = vec![0; block_buff_size as usize];
        //    self.file.read_exact(&mut block_buff).expect("cannot read");

        //    let mut de = ZlibDecoder::new(block_buff.as_slice());
        //    let mut decompressed_buff: Vec<u8> = vec![];
        //    de.read_to_end(&mut decompressed_buff).expect("decompress fail");

        //    let compute_adler32 = adler32::RollingAdler32::from_buffer(&decompressed_buff).hash();
        //    if compute_adler32 != expect_adler32_checksum {
        //        eprintln!("checksum does not match")
        //    }

        //    let mut pos = 0;
        //    while pos < decompressed_buff.len() {
        //        if pos + 8 > decompressed_buff.len() {
        //            break;
        //        }

        //        let record_offset = {
        //            if self.ver == DictFormatVersion::V1 {
        //                let mut buf: [u8; 4] = [0; 4];
        //                buf.clone_from_slice(&decompressed_buff[pos..pos + 4]);
        //                pos += 4;
        //                i32::from_be_bytes(buf) as i64
        //            } else {
        //                let mut buf: [u8; 8] = [0; 8];
        //                buf.clone_from_slice(&decompressed_buff[pos..pos + 8]);
        //                pos += 8;
        //                i64::from_be_bytes(buf)
        //            }
        //        };
        //        let key_text_pos_start = pos;
        //        while let Some(&b) = decompressed_buff.get(pos) {
        //            if self.encoding == Utf16 {
        //                pos += 1;
        //                if let Some(&b1) = decompressed_buff.get(pos) {
        //                    if b == 0 && b1 == 0 {
        //                        break;
        //                    }
        //                } else {
        //                    break;
        //                }
        //            } else if b == 0 {
        //                break;
        //            }
        //            pos += 1;
        //        }

        //        let key_buff = &decompressed_buff[key_text_pos_start..pos];
        //        let item = if self.encoding == Encoding::Utf16 {
        //            let mut buff = key_buff.to_owned();
        //            let utf16_buff = unsafe {
        //                std::slice::from_raw_parts_mut(buff.as_mut_ptr().cast::<u16>(), buff.len() / 2)
        //            };
        //            String::from_utf16_lossy(utf16_buff)
        //        } else {
        //            String::from_utf8_lossy(key_buff).to_string()
        //        };
        //        if item.to_lowercase() == key {
        //            // try read next record_offset;
        //            pos += 1;
        //            let next_record_offset = {
        //                if self.ver == DictFormatVersion::V1 {
        //                    if pos + 4 < decompressed_buff.len() {
        //                        let mut buf: [u8; 4] = [0; 4];
        //                        buf.clone_from_slice(&decompressed_buff[pos..pos + 4]);
        //                        i32::from_be_bytes(buf) as i64
        //                    } else {
        //                        0
        //                    }
        //                } else {
        //                    if pos + 8 < decompressed_buff.len() {
        //                        let mut buf: [u8; 8] = [0; 8];
        //                        buf.clone_from_slice(&decompressed_buff[pos..pos + 8]);
        //                        i64::from_be_bytes(buf)
        //                    } else {
        //                        0
        //                    }
        //                }
        //            };
        //            let data_size = if next_record_offset > record_offset {
        //                next_record_offset - record_offset
        //            } else {
        //                0
        //            };
        //            entry = {
        //                Some(Entry {
        //                    record_offset,
        //                    data_size,
        //                    key: item,
        //                })
        //            };
        //            break;
        //        }
        //        pos += 1;
        //    }
        //}
        //if entry.is_none() {
        //    warn!("cannot find key: {}", key);
        //    return None;
        //}
        //let entry = entry.unwrap();
        //info!("find key: record-offset: {}, key: {}", entry.record_offset, entry.key);

        //// find block
        //// read the  record block
        //let mut block_offset = 0;
        //let mut record_offset = 0;
        //let record_block_index = self.record_block_sect.index.iter().find(|k| {
        //    let b = record_offset + k.decompressed_size > entry.record_offset;
        //    if !b {
        //        record_offset += k.decompressed_size;
        //        block_offset += k.compressed_size;
        //    }
        //    b
        //});
        //if record_block_index.is_none() {
        //    return None;
        //}
        //let record_block_index = record_block_index.unwrap();

        //let block_offset = self.record_block_sect.record_block_offset + block_offset;
        //self.file.seek(SeekFrom::Start(block_offset as u64)).expect("cannot seek");
        //let flag = read_integer!(ByteOrder::LE, u32, self.file);
        //// zip
        //let expect_adler32_checksum = read_integer!(ByteOrder::BE, u32, self.file);
        //let block_buff_size = record_block_index.compressed_size - 4/*flag*/ - 4/*checksum*/;
        //let mut block_buff: Vec<u8> = vec![0; block_buff_size as usize];
        //self.file.read_exact(&mut block_buff).expect("cannot read");

        //if flag == 2 {
        //    let mut de = ZlibDecoder::new(block_buff.as_slice());
        //    let mut decompressed_buff: Vec<u8> = vec![];
        //    de.read_to_end(&mut decompressed_buff).expect("decompress fail");
        //    block_buff = decompressed_buff
        //}

        //let compute_adler32 = adler32::RollingAdler32::from_buffer(&block_buff).hash();
        //if compute_adler32 != expect_adler32_checksum {
        //    eprintln!("checksum does not match")
        //}

        //let relative_offset = (entry.record_offset - record_offset) as usize;
        //let data = if entry.data_size > 0 {
        //    Vec::from(&block_buff[relative_offset..relative_offset + entry.data_size as usize])
        //} else {
        //    Vec::from(&block_buff[relative_offset..])
        //};
        //return Some(Record {
        //    key,
        //    data,
        //});
    }
}

pub struct Record {
    key: String,
    data: Vec<u8>,
}

pub struct Word {
    key: String,
    html: String,
}

pub struct Dict {
    mdx: MdxFile,
    mdd: Vec<MdxFile>,
}

impl Dict {
    pub fn find(&mut self, word: String, case_sensitive: bool) -> Option<Word> {
        let mut record = self.mdx.find(word.clone(), case_sensitive)?;
        if self.mdx.encoding == Utf16 {
            if record.data.len() >= 2 &&
                record.data[record.data.len() - 1] == 0 &&
                record.data[record.data.len() - 2] == 0 {
                record.data.resize(record.data.len() - 2, 0);
            }
        } else if record.data.len() >= 1 && record.data[record.data.len() - 1] == 0 {
            record.data.resize(record.data.len() - 1, 0);
        }

        Some(Word {
            key: record.key,
            html: String::from_utf8_lossy(&record.data).to_string(),
        })
    }

    pub fn find_file(&mut self, word: &str) -> Option<Record> {
        for mdd in &mut self.mdd {
            let record = mdd.find(word.to_string(), false);
            if record.is_some() {
                return record;
            }
        }
        None
    }
}

fn open_dict(p: &str) -> Dict {
    let dir = fs::read_dir(p).expect("cannot open dir")
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>().expect("cannot read dir");

    let mut mdx_file = None;
    let mut mdd = Vec::new();
    for item in dir {
        let file = item.to_str().unwrap();
        info!("processing: {}", file);
        if file.ends_with(".mdx") {
            match MdxFile::parse(file) {
                Ok(mut f) =>
                    match f.load_entries() {
                        Ok(_) => mdx_file = Some(f),
                        Err(e) => panic!("cannot open mdx file: {}", e),
                    }
                Err(e) => panic!("cannot open mdx file: {}", e),
            }
        } else if file.ends_with(".mdd") {
            match MdxFile::parse(item.as_path()) {
                Ok(mut f) =>
                    match f.load_entries() {
                        Ok(_) => mdd.push(f),
                        Err(e) => panic!("cannot open mdx file: {}", e),
                    }
                Err(e) => panic!("cannot open mdx file: {}", e),
            }
        }
    }
    let mdx_file = mdx_file.expect("no mdx file found");

    Dict {
        mdx: mdx_file,
        mdd,
    }
}

fn main() {
    env_logger::init();

    let args = args().collect::<Vec<String>>();
    if args.len() == 1 {
        eprintln!("must provide word list");
        process::abort();
    }
    let word_list = args.get(1).unwrap();

    let mut dicts = vec![
        open_dict("assets/dicts/oxford-v9"),
        open_dict("assets/dicts/longman")];

    if !fs::metadata("out").is_ok() {
        fs::create_dir("out").expect("cannot create dir");
    }

    let mut flash_card_file = fs::File::create("flash-card.csv").expect("cannot create file");
    let word_list = fs::File::open(word_list).expect("cannot open word list");
    let reader = std::io::BufReader::new(word_list);
    for line in reader.lines() {
        if line.is_err() {
            break;
        }

        let input = line.unwrap().trim_end().to_string();
        info!("word: {}", input);
        '_dict: for dict in dicts.as_mut_slice() {
            let mut case_sensitive = dict.mdx.dict_header.key_case_sensitive.to_lowercase() == "no";
            if let Some(mut word) = dict.find(input.clone(), case_sensitive) {
                let mut redirect = 0;
                while word.html.starts_with("@@@LINK=") && redirect < 30 {
                    redirect += 1;
                    let input = word.html.replace("@@@LINK=", "");
                    let input = input.trim_end().to_string();
                    case_sensitive = true;
                    if let Some(w) = dict.find(input, case_sensitive) {
                        word = w;
                    } else {
                        continue '_dict;
                    }
                }


                let mut phon = String::new();

                // search phonic
                if let Some(r) = word.html.find(">NAmE<") {
                    let trimmed = &word.html[r..];
                    {
                        // find phone
                        let r1 = trimmed.find("<phon-blk>");
                        let r2 = trimmed.find("</phon-blk>");
                        if r1.is_some() && r2.is_some() {
                            let r2 = r2.unwrap() + "</phon-blk>".len();
                            phon.push_str(&trimmed[r1.unwrap()..r2]);
                        }
                    }
                    let sound = "<a href=\"sound://";
                    if let Some(sr) = trimmed.find(sound) {
                        let trimmed = &trimmed[sr + sound.len()..];
                        if let Some(r) = trimmed.find("\"") {
                            let sound_file = "\\".to_string() + &trimmed[..r];
                            if let Some(r) = dict.find_file(sound_file.as_str()) {
                                let mp3_file = "out".to_string() + "/" + word.key.as_str() + ".mp3";
                                let mut f = fs::File::create(mp3_file).expect("cannot create file");
                                f.write_all(&r.data).expect("cannot write file");
                            }
                        }
                    }
                }
                // search for longman
                {
                    //<span class="PRON">
                    let phon_tag = "<span class=\"PRON\">";
                    if let Some(r) = word.html.find(phon_tag) {
                        let trimmed = &word.html[r + phon_tag.len()..];
                        if let Some(r) = trimmed.find("</span>") {
                            phon.push_str(&trimmed[..r])
                        }
                        // sound
                        // sound://media/english/ameProns/laadhawkish.mp3
                        let sound_tag = "sound://media/english/ameProns";
                        if let Some(r) = trimmed.find(sound_tag) {
                            let trimmed = &trimmed[r..];
                            if let Some(r) = trimmed.find("\"") {
                                let mp3_href = &trimmed[..r];
                                if mp3_href.ends_with(".mp3") {
                                    let mp3_href = String::from(mp3_href);
                                    let mp3_href = mp3_href.replace("sound:/", "").replace("/", "\\");

                                    if let Some(r) = dict.find_file(mp3_href.as_str()) {
                                        let mp3_file = "out".to_string() + "/" + word.key.as_str() + ".mp3";

                                        let mut f = fs::File::create(mp3_file).expect("cannot create file");
                                        f.write_all(&r.data).expect("cannot write file");
                                    }
                                }
                            }
                        }
                    }
                }

                // save all mp3
                {
                    let mp3_start = "sound:/";
                    let mut pos = 0;
                    while let Some(r) = word.html[pos..].find(mp3_start) {
                        let trimmed = &word.html[pos + r..];
                        let mp3_end = ".mp3";
                        if let Some(r2) = trimmed.find(mp3_end) {
                            let raw_mp3_ref = trimmed[0..r2 + mp3_end.len()].to_owned();

                            let mp3_key = raw_mp3_ref
                                .replace(mp3_start, "")
                                .replace("/", "\\");

                            if mp3_key == "\\".to_string() + word.key.as_str() + ".mp3" {
                                let mp3_key_html = mp3_key.clone().replace("\\", "_");
                                word.html = word.html.replace(&raw_mp3_ref, &mp3_key_html);
                                continue;
                            }

                            let mp3_key_html = mp3_key.clone().replace("\\", "_");

                            let mp3_file = "out/".to_string() + mp3_key_html.as_str();
                            if !fs::metadata(&mp3_file).is_ok() {
                                // extract
                                if let Some(r) = dict.find_file(mp3_key.as_str()) {
                                    let mut f = fs::File::create(&mp3_file).expect("cannot create file");
                                    f.write_all(&r.data).expect("cannot write file");
                                    debug!("mp3 file: {}", mp3_file);

                                    // replace
                                    word.html = word.html.replace(&raw_mp3_ref, &mp3_key_html);
                                }
                            } else {
                                word.html = word.html.replace(&raw_mp3_ref, &mp3_key_html);
                            }
                        }
                        pos += r + mp3_start.len();
                    }
                }
                // search images
                let mut img_count = 0;
                {
                    // img src="thumb_house.png"
                    let img_start = "img src=\"";
                    let mut pos = 0;
                    while let Some(r) = word.html[pos..].find(img_start) {
                        let trimmed = &word.html[pos + r + img_start.len()..];
                        let img_end = "\"";
                        if let Some(r2) = trimmed.find(img_end) {
                            let raw_img_ref = trimmed[0..r2].to_owned();
                            // img is base64
                            let base64_jpg_prefix = "data:image/jpeg;base64,";
                            if raw_img_ref.starts_with(base64_jpg_prefix) {
                                // decode and write to a file
                                let encoded_jpg_data = raw_img_ref[base64_jpg_prefix.len()..r2].to_owned();
                                let img_name = "_base64_".to_string()
                                    + img_count.to_string().as_str()
                                    + word.key.as_str() + ".jpg";
                                let img_file = "out/".to_string() + img_name.as_str();
                                if !fs::metadata(&img_file).is_ok() {
                                    let jpg_data = base64::engine::general_purpose::STANDARD.
                                        decode(encoded_jpg_data).expect("cannot decode");
                                    let mut f = fs::File::create(&img_file).expect("cannot create file");
                                    f.write_all(&jpg_data).expect("cannot write file");
                                    debug!("img file: {}", img_file);
                                }
                                // replace
                                word.html = word.html.replace(&raw_img_ref, &img_name);
                                img_count += 1;
                                pos += base64_jpg_prefix.len();
                                continue;
                            }
                            if !raw_img_ref.ends_with(".png") &&
                                !raw_img_ref.ends_with(".jpg") &&
                                !raw_img_ref.ends_with(".svg") {
                                pos += r + img_start.len();
                                continue;
                            }

                            let img_key = "\\".to_string() + raw_img_ref.replace("/", "\\").as_str();

                            let img_key_html = img_key.clone().replace("\\", "_");

                            let img_file = "out/".to_string() + img_key_html.as_str();
                            if !fs::metadata(&img_file).is_ok() {
                                // extract
                                if let Some(r) = dict.find_file(img_key.as_str()) {
                                    let mut f = fs::File::create(&img_file).expect("cannot create file");
                                    f.write_all(&r.data).expect("cannot write file");
                                    debug!("img file: {}", img_file);

                                    // replace
                                    word.html = word.html.replace(&raw_img_ref, &img_key_html);
                                }
                            } else {
                                word.html = word.html.replace(&raw_img_ref, &img_key_html);
                            }
                        }
                        pos += r + img_start.len();
                    }
                }
                // search base64 images
                {
                    // <img xxxxx src="data:image/jpeg;base64,"
                    let img_start = "src=\"data:image/jpeg;base64,";
                    let mut pos = 0;
                    while let Some(r) = word.html[pos..].find(img_start) {
                        let trimmed = &word.html[pos + r + img_start.len()..];
                        let img_end = "\"";
                        if let Some(r2) = trimmed.find(img_end) {
                            let raw_img_ref = trimmed[0..r2].to_owned();
                            let img_name = "_base64_".to_string()
                                + img_count.to_string().as_str()
                                + word.key.as_str() + ".jpg";
                            let img_file = "out/_base64_".to_string() + img_name.as_str();
                            if !fs::metadata(&img_file).is_ok() {
                                let jpg_data = base64::engine::general_purpose::STANDARD.
                                    decode(&raw_img_ref).expect("cannot decode");
                                let mut f = fs::File::create(&img_file).expect("cannot create file");
                                f.write_all(&jpg_data).expect("cannot write file");
                                debug!("img file: {}", img_file);
                            }
                            // replace
                            let old_str = img_start.to_owned() + raw_img_ref.as_str();
                            let new_str = "src=\"".to_owned() + img_name.as_str();
                            word.html = word.html.replace(&old_str, &new_str);
                            img_count += 1;
                            pos += r + img_start.len();
                            continue;
                        }
                        pos += r + img_start.len();
                    }
                }

                // write flashcard file
                {
                    flash_card_file.write_all(word.key.as_bytes()).expect("");
                    flash_card_file.write_all("|".as_bytes()).expect("");
                    flash_card_file.write_all(phon.as_bytes()).expect("");
                    flash_card_file.write_all("|".as_bytes()).expect("");
                    // example
                    flash_card_file.write_all("|".as_bytes()).expect("");

                    flash_card_file.write_all(r#"<html lang="en"><meta charset="UTF-8">"#.as_bytes()).expect("cannot write");

                    let mut html = word.html.replace("|", "/");
                    if html.as_bytes().len() >= 131072 {
                        let s = &html.as_bytes()[..131072];
                        html = String::from_utf8_lossy(s).to_string();
                    }
                    let html = html.trim();
                    flash_card_file.write_all(html.as_bytes()).expect("cannot write");

                    flash_card_file.write_all("|".as_bytes()).expect("");
                    flash_card_file.write_all(("[sound:".to_string() + word.key.as_str() + ".mp3]").as_bytes()).expect("");
                    flash_card_file.write_all("\n".as_bytes()).expect("");
                }
                break;
            } else {
                warn!("cannot find word: {}", input);
            }
        }
    }
}

fn decrypt(data: &mut Vec<u8>, checksum: u32) {
    use ripemd128::{Ripemd128, Digest};
    let mut hasher = Ripemd128::new();
    Digest::input(&mut hasher, checksum.to_be_bytes());
    Digest::input(&mut hasher, vec![0x95, 0x36, 0, 0]);
    let key = hasher.result();

    let mut previous = 0x36;
    for i in 0..data.len() {
        let v = {
            (data[i] >> 4) | (data[i] << 4)
        };
        let v = v ^ previous ^ key[i % key.len()] ^ (i as u8);
        previous = data[i];
        data[i] = v;
    }
}
