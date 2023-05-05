/**
 * Replace to target bytes vector by bytes vector
 */
pub fn range_byte_replace<'a>(vec: &'a mut Vec<u8>, start: usize, data: Vec<u8>) -> &'a Vec<u8> {
    let end = start + data.len();
    vec.splice(start..end, data);
    vec
}

pub fn get_padding(num: u8, size: usize) -> Vec<u8> {
    let mut vec = vec![num];
    while size > vec.len() && size != vec.len() {
        vec.insert(0, 0);
    }
    vec
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn range_byte_replace_test() {
        let mut v: Vec<u8> = vec![0; 5];
        let g: Vec<u8> = vec![1, 2, 3];
        range_byte_replace(&mut v, 1, g);
        assert_eq!(v, [0, 1, 2, 3, 0]);
    }

    #[test]
    fn get_bytes_with_padding_test() {
        let v = get_padding(10, 3);
        assert_eq!(v, [0, 0, 10]);
    }
}