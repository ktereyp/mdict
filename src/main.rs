extern crate core;

use std::{fs};
use std::mem::size_of;
use std::io::{Read, Seek, SeekFrom};
use log::{info, error, warn};

use adler32;

use serde::{Deserialize};
use serde_xml_rs::{from_str};

use flate2::read::ZlibDecoder;

#[allow(dead_code)]
enum ByteOrder {
    LE,
    BE,
}

macro_rules! read_integer {
    (ByteOrder::LE, $x: ty, $r: tt) => {
        {
            const LENGTH: usize = size_of::<$x>();
            let mut buff: [u8; LENGTH] = [0; LENGTH];
            $r.read(&mut buff).expect("cannot read");
            <$x>::from_le_bytes(buff)
        }
    };
    (ByteOrder::BE, $x: ty, $r: tt) => {
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
struct DictInfo {
    generated_by_engine_version: String,
    required_engine_version: String,
    encrypted: i32,
    encoding: String,
    format: String,
    creation_date: String,
    compact: String,
    compat: String,
    key_case_sensitive: String,
    description: String,
    title: String,
    data_source_format: String,
    style_sheet: String,
    register_by: String,
    reg_code: String,
}

#[derive(Default, Debug)]
struct KeyIndexSection {
    offset: i32,
    key_block_data_offset: i32,
    num_blocks: i32,
    num_entries: i32,
    key_block_info_bytes_len: i32,
    key_block_data_len: i32,
    index: Vec<KeyBlockInfo>,
    entries: Vec<Entry>,
}

#[derive(Default, Debug)]
struct Entry {
    record_offset: i32,
    key: String,
}

#[derive(Default, Debug)]
struct KeyBlockInfo {
    number_of_entries: i32,
    first: String,
    last: String,
    compressed_size: i32,
    decompressed_size: i32,
}

#[derive(Default, Debug)]
struct RecordBlockIndex {
    compressed_size: i32,
    decompressed_size: i32,
}

#[derive(Default, Debug)]
struct RecordBlockSection {
    offset: i32,
    record_block_offset: i32,
    number_of_record_block: i32,
    number_of_entries: i32,
    record_index_data_size: i32,
    record_block_data_size: i32,
    index: Vec<RecordBlockIndex>,
}

fn main() {
    env_logger::init();

    let mut f = fs::File::open("oxford-v9/V2.0.mdx").expect("cannot open file");
    let header_len = read_integer!(ByteOrder::BE, i32, f);
    let (header_content, check_sum) = {
        let mut header_content_bytes: Vec<u8> = vec![0; header_len as usize];
        f.read_exact(&mut header_content_bytes).expect("cannot read");

        let adler = adler32::RollingAdler32::from_buffer(&header_content_bytes);

        let header_content_u16 = unsafe {
            std::slice::from_raw_parts_mut(header_content_bytes.as_mut_ptr().cast::<u16>(), header_content_bytes.len() / 2)
        };
        (String::from_utf16_lossy(header_content_u16), adler.hash())
    };
    let exp_check_sum = read_integer!(ByteOrder::LE, u32, f);
    if exp_check_sum != check_sum {
        println!("check sum not match");
        return;
    }
    let dict_info: DictInfo = from_str(&header_content).unwrap();
    println!("engine version: {:#?}", dict_info);
    let key_index_offset = 4 + header_len + 4;

    let mut key_index_section = KeyIndexSection::default();
    key_index_section.offset = key_index_offset;
    key_index_section.num_blocks = read_integer!(ByteOrder::BE, i32, f);
    key_index_section.num_entries = read_integer!(ByteOrder::BE, i32, f);
    key_index_section.key_block_info_bytes_len = read_integer!(ByteOrder::BE, i32, f);
    key_index_section.key_block_data_len = read_integer!(ByteOrder::BE, i32, f);
    key_index_section.key_block_data_offset = key_index_section.offset
        + 4 * 4
        + key_index_section.key_block_info_bytes_len;
    println!("key block info: {:#?}", key_index_section);

    // load key index
    for _ in 0..key_index_section.num_blocks {
        let mut key_block_info = KeyBlockInfo::default();
        key_block_info.number_of_entries = read_integer!(ByteOrder::BE, i32, f);

        let first_len = read_integer!(ByteOrder::BE, i8, f);
        let mut first_content: Vec<u8> = vec![0; first_len as usize];
        f.read_exact(&mut first_content).expect("cannot read");
        key_block_info.first = String::from_utf8_lossy(&first_content).to_string();

        let last_len = read_integer!(ByteOrder::BE, i8, f);
        let mut last_content: Vec<u8> = vec![0; last_len as usize];
        f.read_exact(&mut last_content).expect("cannot read");
        key_block_info.last = String::from_utf8_lossy(&last_content).to_string();

        key_block_info.compressed_size = read_integer!(ByteOrder::BE, i32, f);
        key_block_info.decompressed_size = read_integer!(ByteOrder::BE, i32, f);

        //println!("key block info: {:#?}", key_block_info);
        key_index_section.index.push(key_block_info);
    }
    // load key block index
    let mut record_block_sect = RecordBlockSection::default();
    {
        record_block_sect.offset = key_index_offset  // key index offset
            + 4 // big-endian i32 of this four bytes is the number of key blocks
            + 4 // big-endian i32 of this four bytes is the number of words
            + 4 // big-endian i32 of this four bytes is total size of key block info
            + 4 // big-endian i32 of this four bytes is total size of key blocks
            + key_index_section.key_block_info_bytes_len // total size of key block info
            + key_index_section.key_block_data_len;     // total size of key blocks
        f.seek(SeekFrom::Start(record_block_sect.offset as u64)).expect("cannot seek");
        {
            record_block_sect.number_of_record_block = read_integer!(ByteOrder::BE, i32, f);
            record_block_sect.number_of_entries = read_integer!(ByteOrder::BE, i32, f);
            record_block_sect.record_index_data_size = read_integer!(ByteOrder::BE, i32, f);
            record_block_sect.record_block_data_size = read_integer!(ByteOrder::BE, i32, f);

            record_block_sect.record_block_offset = record_block_sect.offset
                + 4 * 4 // four i32 length
                + record_block_sect.record_index_data_size;

            for _ in 0..record_block_sect.number_of_record_block {
                let cz = read_integer!(ByteOrder::BE, i32, f);
                let dz = read_integer!(ByteOrder::BE, i32, f);
                record_block_sect.index.push(RecordBlockIndex {
                    compressed_size: cz,
                    decompressed_size: dz,
                });
            }
        }
    }

    // find word
    loop {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let input = input.trim_end().to_string();
        info!("word: {}", input);
        let begin = std::time::SystemTime::now();
        // find index
        let mut key_block_offset = 0;
        let key_block_info = key_index_section.index.iter().find(|k| {
            let b = k.first <= input && k.last >= input;
            if !b {
                key_block_offset += k.compressed_size
            }
            b
        });
        if key_block_info.is_none() {
            warn!("cannot find key index for word '{}'", input);
            continue;
        }
        let key_block_info = key_block_info.unwrap();

        // read key block
        let mut entry = None;
        {
            let key_block_offset = key_block_offset + key_index_section.key_block_data_offset;
            f.seek(SeekFrom::Start(key_block_offset as u64)).expect("cannot seek");
            let flag = read_integer!(ByteOrder::LE, i32, f);
            if flag != 2 {
                warn!("not zlib compress");
                continue;
            }
            let expect_adler32_checksum = read_integer!(ByteOrder::BE, u32, f);

            let block_buff_size = key_block_info.compressed_size - 4 /*compress type*/ - 4 /* checksum*/;
            let mut block_buff: Vec<u8> = vec![0; block_buff_size as usize];
            f.read_exact(&mut block_buff).expect("cannot read");

            let mut de = ZlibDecoder::new(block_buff.as_slice());
            let mut decompressed_buff: Vec<u8> = vec![];
            de.read_to_end(&mut decompressed_buff).expect("decompress fail");

            let compute_adler32 = adler32::RollingAdler32::from_buffer(&decompressed_buff).hash();
            if compute_adler32 != expect_adler32_checksum {
                eprintln!("checksum does not match")
            }

            let mut pos = 0;
            while pos < decompressed_buff.len() {
                if pos + 8 > decompressed_buff.len() {
                    break;
                }
                let mut buf: [u8; 4] = [0; 4];
                buf.clone_from_slice(&decompressed_buff[pos..pos + 4]);
                let record_offset = i32::from_be_bytes(buf);
                pos += 4;
                let key_text_pos_start = pos;
                while let Some(&b) = decompressed_buff.get(pos) {
                    if b == 0 {
                        break;
                    }
                    pos += 1;
                }

                let key = String::from_utf8_lossy(&decompressed_buff[key_text_pos_start..pos]).to_string();
                if key == input {
                    entry = Some(Entry {
                        record_offset,
                        key,
                    });
                    break;
                }
                pos += 1;
            }
        }
        if entry.is_none() {
            warn!("cannot find key for word: {}", input);
            continue;
        }
        let entry = entry.unwrap();
        info!("find key: record-offset: {}, key: {}", entry.record_offset, entry.key);

        // find block
        {
            // read the  record block
            let mut block_offset = 0;
            let mut record_offset = 0;
            let record_block_index = record_block_sect.index.iter().find(|k|{
                let b  = record_offset + k.decompressed_size > entry.record_offset;
                if !b {
                    record_offset += k.decompressed_size;
                    block_offset += k.compressed_size;
                }
                b
            });
            if record_block_index.is_none(){
                warn!("no record block find for word: {}", input);
                continue;
            }
            let record_block_index = record_block_index.unwrap();

            let block_offset = record_block_sect.record_block_offset + block_offset;
            f.seek(SeekFrom::Start(block_offset as u64)).expect("cannot seek");
            let flag = read_integer!(ByteOrder::LE, u32, f);
            if flag == 2 {
                // zip
                let expect_adler32_checksum = read_integer!(ByteOrder::BE, u32, f);
                let block_buff_size = record_block_index.compressed_size - 4/*flag*/ - 4/*checksum*/;
                let mut block_buff: Vec<u8> = vec![0; block_buff_size as usize];
                f.read_exact(&mut block_buff).expect("cannot read");

                let mut de = ZlibDecoder::new(block_buff.as_slice());
                let mut decompressed_buff: Vec<u8> = vec![];
                de.read_to_end(&mut decompressed_buff).expect("decompress fail");

                let compute_adler32 = adler32::RollingAdler32::from_buffer(&decompressed_buff).hash();
                if compute_adler32 != expect_adler32_checksum {
                    eprintln!("checksum does not match")
                }

                let relative_offset = entry.record_offset - record_offset;

                let mut pos = relative_offset as usize;
                while pos < decompressed_buff.len() {
                    let key_text_pos_start = pos;
                    while let Some(&b) = decompressed_buff.get(pos) {
                        if b == 0 {
                            break;
                        }
                        pos += 1;
                    }

                    let record_text = String::from_utf8_lossy(&decompressed_buff[key_text_pos_start..pos]).to_string();
                    println!("pos: {}, {}", key_text_pos_start, record_text);
                    break;
                }
            }
        }
    }

    // load all key block info
    {
        for key_block_info in &key_index_section.index {
            let flag = read_integer!(ByteOrder::LE, i32, f);
            let expect_adler32_checksum = read_integer!(ByteOrder::BE, u32, f);

            let block_buff_size = key_block_info.compressed_size - 4 /*compress type*/ - 4 /* checksum*/;
            let mut block_buff: Vec<u8> = vec![0; block_buff_size as usize];
            f.read_exact(&mut block_buff).expect("cannot read");

            let mut de = ZlibDecoder::new(block_buff.as_slice());
            let mut decompressed_buff: Vec<u8> = vec![];
            de.read_to_end(&mut decompressed_buff).expect("decompress fail");

            let compute_adler32 = adler32::RollingAdler32::from_buffer(&decompressed_buff).hash();
            if compute_adler32 != expect_adler32_checksum {
                eprintln!("checksum does not match")
            }

            let mut pos = 0;
            while pos < decompressed_buff.len() {
                if pos + 8 > decompressed_buff.len() {
                    break;
                }
                let mut buf: [u8; 4] = [0; 4];
                buf.clone_from_slice(&decompressed_buff[pos..pos + 4]);
                let record_offset = i32::from_be_bytes(buf);
                pos += 4;
                let key_text_pos_start = pos;
                while let Some(&b) = decompressed_buff.get(pos) {
                    if b == 0 {
                        break;
                    }
                    pos += 1;
                }

                let key = String::from_utf8_lossy(&decompressed_buff[key_text_pos_start..pos]).to_string();
                key_index_section.entries.push(Entry {
                    record_offset,
                    key,
                });

                pos += 1;
            }
        }
    }

    // record section
    let mut record_block_sect = RecordBlockSection::default();
    record_block_sect.offset = key_index_offset  // key index offset
        + 4 // big-endian i32 of this four bytes is the number of key blocks
        + 4 // big-endian i32 of this four bytes is the number of words
        + 4 // big-endian i32 of this four bytes is total size of key block info
        + 4 // big-endian i32 of this four bytes is total size of key blocks
        + key_index_section.key_block_info_bytes_len // total size of key block info
        + key_index_section.key_block_data_len;     // total size of key blocks
    f.seek(SeekFrom::Start(record_block_sect.offset as u64)).expect("cannot seek");
    {
        record_block_sect.number_of_record_block = read_integer!(ByteOrder::BE, i32, f);
        record_block_sect.number_of_entries = read_integer!(ByteOrder::BE, i32, f);
        record_block_sect.record_index_data_size = read_integer!(ByteOrder::BE, i32, f);
        record_block_sect.record_block_data_size = read_integer!(ByteOrder::BE, i32, f);

        record_block_sect.record_block_offset = record_block_sect.offset
            + 4 * 4 // four i32 length
            + record_block_sect.record_index_data_size;

        for _ in 0..record_block_sect.number_of_record_block {
            let cz = read_integer!(ByteOrder::BE, i32, f);
            let dz = read_integer!(ByteOrder::BE, i32, f);
            record_block_sect.index.push(RecordBlockIndex {
                compressed_size: cz,
                decompressed_size: dz,
            });
        }

        // read the  record block
        let block_num = 1;
        let mut block_offset = 0;
        for i in 0..block_num {
            block_offset += record_block_sect.index.get(i).unwrap().compressed_size;
        }
        let block_offset = record_block_sect.record_block_offset + block_offset;
        f.seek(SeekFrom::Start(block_offset as u64)).expect("cannot seek");
        let flag = read_integer!(ByteOrder::LE, u32, f);
        if flag == 2 {
            // zip
            let expect_adler32_checksum = read_integer!(ByteOrder::BE, u32, f);
            let block_info = record_block_sect.index.get(block_num).unwrap();
            let block_buff_size = block_info.compressed_size - 4/*flag*/ - 4/*checksum*/;
            let mut block_buff: Vec<u8> = vec![0; block_info.compressed_size as usize];
            f.read_exact(&mut block_buff).expect("cannot read");

            let mut de = ZlibDecoder::new(block_buff.as_slice());
            let mut decompressed_buff: Vec<u8> = vec![];
            de.read_to_end(&mut decompressed_buff).expect("decompress fail");

            let compute_adler32 = adler32::RollingAdler32::from_buffer(&decompressed_buff).hash();
            if compute_adler32 != expect_adler32_checksum {
                eprintln!("checksum does not match")
            }

            let mut pos = 0;
            while pos < decompressed_buff.len() {
                let key_text_pos_start = pos;
                while let Some(&b) = decompressed_buff.get(pos) {
                    if b == 0 {
                        break;
                    }
                    pos += 1;
                }

                let record_text = String::from_utf8_lossy(&decompressed_buff[key_text_pos_start..pos]).to_string();
                println!("pos: {}, {}", key_text_pos_start, record_text);
                pos += 1;
                break;
            }
        }
    }
}

