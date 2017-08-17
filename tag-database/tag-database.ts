import { Element, ElementType } from './element';
import { Tag, TLV, TLVParser, ByteArray } from './tlv';
import { Context } from './context';

let entries: Element[] = [
  { id: 'PAN', type: ElementType.BCD, minSizeBits: 12*8, maxSizeBits: 19*8, tag: new ByteArray( [ 0x5A ] ), description: "Primary Account Number" },

  { id: 'TVR', type: ElementType.TYPE, minSizeBits: 5*8, tag: new ByteArray( [ 0x95 ] ),
    childElements: [
      { id: 'B1.8', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits:    7,  description: 'Offline data authentication was not performed' },
      { id: 'B1.7', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits:    6,  description: 'SDA failed' },
      { id: 'B1.6', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits:    5,  description: 'ICC data missing' },
      { id: 'B1.5', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits:    4,  description: 'Card appears on terminal exception file' },
      { id: 'B1.4', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits:    3,  description: 'DDA failed' },
      { id: 'B1.3', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits:    2,  description: 'CDA failed' },

      { id: 'B2.8', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits:  8+7,  description: 'ICC and terminal have different application versions' },
      { id: 'B2.7', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits:  8+6,  description: 'Expired application' },
      { id: 'B2.6', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits:  8+5,  description: 'Application not yet effective' },
      { id: 'B2.5', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits:  8+4,  description: 'Requested service not allowed for card product' },
      { id: 'B2.4', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits:  8+3,  description: 'New card' },

      { id: 'B3.8', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits: 16+7,  description: 'Cardholder verification was not successful' },
      { id: 'B3.7', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits: 16+6,  description: 'Unrecognised CVM' },
      { id: 'B3.6', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits: 16+5,  description: 'PIN Try Limit exceeded' },
      { id: 'B3.5', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits: 16+4,  description: 'PIN entry required and PIN pad not present or not working' },
      { id: 'B3.4', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits: 16+3,  description: 'PIN entry required, PIN pad present, but PIN was not entered' },
      { id: 'B3.3', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits: 16+2,  description: 'Online PIN entered' },

      { id: 'B4.8', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits: 24+7,  description: 'Transaction exceeds floor limit' },
      { id: 'B4.7', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits: 24+6,  description: 'Lower consecutive offline limit exceeded' },
      { id: 'B4.6', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits: 24+5,  description: 'Upper consecutive offline limit exceeded' },
      { id: 'B4.5', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits: 24+4,  description: 'Transaction selected randomly for online processing' },
      { id: 'B4.4', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits: 24+3,  description: 'Merchant forced transaction online' },

      { id: 'B5.8', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits: 32+7,  description: 'Default TDOL used' },
      { id: 'B5.7', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits: 32+6,  description: 'Issuer authentication failed' },
      { id: 'B5.6', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits: 32+5,  description: 'Script processing failed before final GENERATE AC' },
      { id: 'B5.5', type: ElementType.BOOLEAN, minSizeBits: 1, offsetBits: 32+4,  description: 'Script processing failed after final GENERATE AC' },
    ]
  },
];

interface TLVParserConstructor {
    new(...args: any[]): TLVParser;
}

export class TagDatabase {
  parserCtor: TLVParserConstructor;
  entries: Element[];

  constructor( parserCtor: TLVParserConstructor ) {
    this.parserCtor = parserCtor;
    this.entries = entries;
  }

  findElement( tlv: TLV): Element | undefined {
    let el = this.entries.find( (e) => {
      return !!e.tag && e.tag.equals( tlv.tag );
    });

    return el;
  }

  checkElement( el: Element, buffer: ByteArray, bufferBits?: number ): boolean {
    let firstBit = el.offsetBits || 0;
    let nextBit = firstBit + (el.minSizeBits || 1);

    bufferBits = bufferBits || buffer.length * 8;

    // Check size
    if ( nextBit > bufferBits )
      return false;

    return true;
  }

  private parseTLV( el: Element, tlv: TLV ) {
    console.log( "Got an El")
  }

  parseBuffer( buffer: ByteArray ) {
    let parser = new this.parserCtor( buffer );

    while( parser.more ) {
      console.log( " ptag:" + parser.peekTag().toHexString() );
      let tlv = parser.nextTLV();
      console.log( "  ** Extract" );
      console.log( "  tag:" + tlv.tag.toHexString() );
      console.log( "  len:" + tlv.length );
      console.log( "  val:" + tlv.value.toHexString() );

      let el = this.findElement( tlv );
      if ( el ) {
        this.checkElement( el, tlv.value )
        this.parseTLV( el, tlv );
      }
    }

  }

}
