pub fn format_u16(mut port: u16, buf: &mut [u8; 5]) -> usize {
    let mut cursor = 0;
    if port >= 10 {
        if port >= 100 {
            if port >= 1000 {
                if port >= 10000 {
                    buf[cursor] = (b'0' as u16 + port / 10000) as u8;
                    cursor += 1;
                    port %= 10000;
                }
                buf[cursor] = (b'0' as u16 + port / 1000) as u8;
                cursor += 1;
                port %= 1000;
            }
            buf[cursor] = (b'0' as u16 + port / 100) as u8;
            cursor += 1;
            port %= 100;
        }
        buf[cursor] = (b'0' as u16 + port / 10) as u8;
        cursor += 1;
        port %= 10;
    }
    buf[cursor] = (b'0' as u16 + port) as u8;
    cursor + 1
}
