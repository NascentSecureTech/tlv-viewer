import { ByteArray } from './tlv';

export enum ElementType {
  TYPE,
  ELEMENT,
  BCD,
  BOOLEAN,
  INTEGER,
}

export interface Element {
  id?: string;
  tag?: ByteArray,
  name?: string;
  description?: string;
  type: ElementType;
  inherits?: string;

  minSizeBits?: number;
  maxSizeBits?: number;

  offsetBits?: number;

  childElements?: Element[];
}
