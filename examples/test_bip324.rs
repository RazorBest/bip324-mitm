use bip324_mitm::bip324::new_handshake_pair;
use bip324_mitm::key_from_secret_bytes;
use bip324_mitm::protocol::{MAINNET_MAGIC, Role};
use hex_literal::hex;

use bip324_mitm::state_machine::{StreamReadParser, StreamWriteParser};

fn main() {
    let key_initiator = key_from_secret_bytes(hex!(
        "6a34b0f8757abbd31934ce6375857b06000d1a4528274eaec46c6e11a243366d"
    ))
    .unwrap();
    let key_responder = key_from_secret_bytes(hex!(
        "6a34b0f8757abbd31934ce6375857b06000d1a4528274eaec46c6e11a243366a"
    ))
    .unwrap();
    let (mut reader1, mut writer1) =
        new_handshake_pair(Role::Initiator, MAINNET_MAGIC, key_initiator);
    let (mut reader2, mut writer2) =
        new_handshake_pair(Role::Responder, MAINNET_MAGIC, key_responder);

    writer1.push_garbage_bytes(&[13u8; 133]);

    let mut data = vec![0u8; 512];
    let (data1, _data2) = data.split_at_mut(300);
    let data1_len = data1.len();
    let mut buf1 = &mut data1[..];

    writer1.produce(&mut buf1).unwrap();
    println!("Written1: {}", data1_len - buf1.len());

    writer1.push_garbage_bytes(&[13u8; 10]);
    writer1.produce(&mut buf1).unwrap();
    println!("Written1: {}", data1_len - buf1.len());
    writer1.set_garbage_eof();

    writer1.produce(&mut buf1).unwrap();
    println!("Written1: {}", data1_len - buf1.len());

    {
        let written_len = data1_len - buf1.len();
        let d1 = &data1[..written_len];
        let d1_len = d1.len();
        let mut buf1 = d1;

        reader2.consume(&mut buf1).unwrap();
        println!("Read2: {}", d1_len - buf1.len());
    }

    let mut buf1 = &mut data1[..];
    writer2.push_garbage_bytes(&[66u8; 35]);
    writer2.set_garbage_eof();
    writer2.produce(&mut buf1).unwrap();
    println!("Written2: {}", data1_len - buf1.len());
    writer2.produce(&mut buf1).unwrap();
    println!("Written2: {}", data1_len - buf1.len());

    {
        let d1 = &data1[..];
        let d1_len = d1.len();
        let mut buf1 = d1;
        reader1.consume(&mut buf1).unwrap();
        println!("Read1: {}", d1_len - buf1.len());
    }

    let mut data3 = vec![0u8; 1024];
    let data3_len = data3.len();
    let mut buf3 = &mut data3[..];
    writer1.produce(&mut buf3).unwrap();
    println!("Written1: {}", data3_len - buf3.len());

    {
        let written_len = data3_len - buf3.len();
        let d1 = &data3[..written_len];
        let d1_len = d1.len();
        let mut buf1 = d1;

        reader2.consume(&mut buf1).unwrap();
        println!("Read2: {}", d1_len - buf1.len());
    }

    let mut writer1 = writer1.into_data_writer();

    let mut data3 = vec![0u8; 1024];
    let data3_len = data3.len();
    let mut buf3 = &mut data3[..];
    writer1.produce(&mut buf3).unwrap();
    println!("Written1: {}", data3_len - buf3.len());

    // I don't like the fact that you can push how much you want
    writer1.push_length_bytes(&[0u8, 0u8, 0u8]);
    writer1.push_data_bytes(&[1u8]);
    writer1.push_tag_bytes(&[1u8; 16]);

    let mut data3 = vec![0u8; 1024];
    let data3_len = data3.len();
    let mut buf3 = &mut data3[..];
    writer1.produce(&mut buf3).unwrap();
    let buf3_len = buf3.len();
    println!("Written1: {}", data3_len - buf3.len());

    // Should be 0 because we didn't convert to DataReader
    {
        let written_len = data3_len - buf3_len;
        let d1 = &data3[..written_len];
        let d1_len = d1.len();
        let mut buf1 = d1;

        println!("Reading2 data: {:?}", buf1);
        reader2.consume(&mut buf1).unwrap();
        println!("Read2: {}", d1_len - buf1.len());
    }

    let (mut reader2, aad_r2) = reader2.into_data_reader();

    println!("Reader2 aad: {:?}", aad_r2);

    {
        let written_len = data3_len - buf3_len;
        let d1 = &data3[..written_len];
        let d1_len = d1.len();
        let mut buf1 = d1;

        reader2.consume(&mut buf1).unwrap();
        println!("Read2: {}", d1_len - buf1.len());
    }

    println!("Reader2 length: {:?}", reader2.drain_length_bytes());
    println!("Reader2 data: {:?}", reader2.drain_data_bytes());
    println!("Reader2 tag: {:?}", reader2.drain_tag_bytes());

    let _writer2 = writer2.into_data_writer();
}
