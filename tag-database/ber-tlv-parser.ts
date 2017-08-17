import { Tag, ByteArray, TLV, TLVParser, TLVParseFlags } from './tlv';

const emptyByteArray = new ByteArray( 0 );
const emptyTag = new Tag( emptyByteArray );
const emptyTLV: TLV = {
    tag: emptyTag,
    length: 0,
    value: emptyByteArray
  }

interface ParseInfo {
  tlv: TLV;
  tagOffset: number;
  tagLen: number;
  lenLen: number;
  tlvLen: number;
}

export class BERTLVParser implements TLVParser {
  readonly buffer: ByteArray;
  private offset: number;

  /**
  * NULL: Error
  * tag = undefined => no data
  **/
  private parseTLV( advance: boolean, flags: TLVParseFlags ) : ParseInfo | null {
    let info: ParseInfo = {
      tlv: { ...emptyTLV },
      tagOffset: 0,
      tagLen: 0,
      lenLen: 0,
      tlvLen: 0
    };
    let tlv = info.tlv;

    let offset = this.offset;
    let buffer = this.buffer;

    // Skip initial padding ..
    while( offset < buffer.length ) {
      if ( buffer[ offset ] != 0x00 )
        break;

      this.offset = ++offset;
    }

    // extract tag ?
    info.tagOffset = offset;
    if ( flags & TLVParseFlags.TAG ) {
      while( offset < buffer.length ) {
        let tagByte = buffer[ offset++ ];

        info.tagLen = offset - info.tagOffset;

        if ( info.tagLen == 1 )
        {
          if ( ( tagByte & 0x1F ) != 0x1F )
            break;
        }
        else {
          if ( ( tagByte & 0x80 ) == 0x00 )
            break;
        }
      }

      // Found a tag?
      if ( offset > info.tagOffset )
        tlv.tag = new Tag( new ByteArray( buffer.slice( info.tagOffset, info.tagLen ) ) );
      else
        return null; // Error, no tag
    }

    // extract length?
    if ( flags & TLVParseFlags.LEN ) {
      let lenOffset = offset;
      let lenLen = 1;

      while( offset < buffer.length ) {
        let lenByte = buffer[ offset++ ];

        // first byte of Length ?
        if ( offset - lenOffset == 1 ) {
          if ( lenByte & 0x80 ) {
            lenLen = lenByte & 0x7F;
          }
          else {
            tlv.length = lenByte;
          }
        }
        else {
          tlv.length = (tlv.length << 8) | lenByte;
        }

        if ( --lenLen == 0 )
          break;
      }

      if ( lenLen > 0 )
        return null; // Error, no length
    }

    if ( flags & TLVParseFlags.VALUE ) {

      if ( offset + tlv.length <= buffer.length ) {
        tlv.value = new ByteArray( buffer.slice( offset, offset + tlv.length ) );
        offset += tlv.length;
      }
      else
        return null; // Error, value too large
    }

    info.tlvLen = offset - this.offset;

    return info;
  }

  constructor( buffer: ByteArray ) {
    this.buffer = buffer;
    this.rewind();
  }

  rewind() {
    this.offset = 0;
  }

  get pos() {
    return this.offset;
  }

  get more() {
    let tlv = this.parseTLV( false, TLVParseFlags.ALL );

    return !!tlv;
  }

  skip() {
    this.parseTLV( true, TLVParseFlags.ALL );
  }

  peekTag(): Tag {
    let info = this.parseTLV( false, TLVParseFlags.TAG );

    return ( info ) ? info.tlv.tag : emptyTag;
  }

  nextTLV(): TLV {
    let info = this.parseTLV( false, TLVParseFlags.ALL );

    if ( info ) {
      this.offset += info.tlvLen;

      return info.tlv;
    }

    return { ...emptyTLV };
  }

  nextValue(): ByteArray {
    let info = this.parseTLV( false, TLVParseFlags.ALL );

    if ( info ) {
      this.offset += info.tlvLen;

      return info.tlv.value;
    }

    return emptyByteArray;
  }

  nextValueAsParser(): TLVParser {
    return new BERTLVParser( this.nextValue() );
  }
}
