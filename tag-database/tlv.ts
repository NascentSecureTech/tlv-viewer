export class ByteArray extends Uint8Array {
  static fromHexString( hex: string ): ByteArray {
    let s = hex.replace( ' ', '' );
    let bytes = new ByteArray( s.length /2 );

    for( let i = 0; i < bytes.length; ++i )
    {
      bytes[i] = parseInt(s.substr( i * 2, 2 ), 16)
    }

    return bytes;
  }

  toHexString(): String {
    var s = '';

    this.forEach( ( byte: number) => {
      s += ('0' + byte.toString(16)).slice(-2);
    });

    return s;
  }

  equals( other: ByteArray ): boolean {
    let ok = this.length == other.length;

    if ( ok ) {
      ok = ok && !this.some( ( val, idx ) => { return val != other[idx]; } );
    }

    return ok;
  }
};

export class Tag extends ByteArray {
  get tagLength(): number {
    return this.tagLength
  }

  get tagAsNum(): number {
    let tag = 0;

    this.forEach( byte => { tag = tag << 8 + byte } );

    return tag;
  }

  get tagAsString(): String {
    return String.fromCharCode.apply(null, this);
  }

  get tagAsHexString(): String {
    return this.toHexString();
  }
}

export interface TLV {
  tag: Tag;
  length: number;
  value: ByteArray;
}

export enum TLVParseFlags {
  TAG   = 1 << 0,
  LEN   = 1 << 1,
  VALUE = 1 << 2,
  ALL   = TAG | LEN | VALUE
}

export interface TLVParser {
  readonly buffer: ByteArray;
  readonly pos: number;
  readonly more: boolean;

  rewind(): void;
  skip(): void;

  peekTag(): Tag;

  nextTLV(): TLV;
  nextValue(): ByteArray;
  nextValueAsParser(): TLVParser;
}
