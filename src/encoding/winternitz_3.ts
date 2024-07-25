import { bigintToBufferBE, hash, toNibbles } from "./encoding";

const winternitzSecret = 0x92654528273736353537775533553553874383876346n;

function getWinternitzPrivateKey_3(index: number): bigint {
    return hash(winternitzSecret + BigInt(index));
}

function getWinternitzPublicKey_3(index: number): bigint {
    return hash(getWinternitzPrivateKey_3(index), 8);
}

export function getWinternitzPrivateKeys32_3(chunkIndex: number): bigint[] {
    const t: bigint[] = [];
    for (let i = 0; i < 14; i++) {
        t.push(getWinternitzPrivateKey_3(chunkIndex * 14 + i));
    }
    return t;
}

export function getWinternitzPublicKeys32_3(chunkIndex: number): bigint[] {
    const t: bigint[] = [];
    for (let i = 0; i < 14; i++) {
        t.push(getWinternitzPublicKey_3(chunkIndex * 14 + i));
    }
    return t;
}

export function getWinternitzPrivateKeys256_3(chunkIndex: number): bigint[] {
    const t: bigint[] = [];
    for (let i = 0; i < 90; i++) {
        t.push(getWinternitzPrivateKey_3(chunkIndex * 90 + i));
    }
    return t;
}

export function getWinternitzPublicKeys256_3(chunkIndex: number): bigint[] {
    const t: bigint[] = [];
    for (let i = 0; i < 90; i++) {
        t.push(getWinternitzPublicKey_3(chunkIndex * 90 + i));
    }
    return t;
}

export function encodeWinternitz32_3(input: bigint, chunkIndex: number): Buffer {
    const checksumNibbles = 3;
    const dataNibbles = 11;
    const hashSizeBytes = 32;
    let output = Buffer.from([]);
    let checksum = 0;
    const privateKeys = getWinternitzPrivateKeys32_3(chunkIndex);
    toNibbles(input, dataNibbles, 3).forEach((nibble, i) => {
        checksum += nibble;
        const t = 7 - nibble;
        output = Buffer.concat([output, bigintToBufferBE(hash(privateKeys[i], t), hashSizeBytes)]);
    });
    toNibbles(BigInt(checksum), checksumNibbles, 3).forEach((nibble, i) => {
        output = Buffer.concat([output, bigintToBufferBE(hash(privateKeys[11 + i], nibble), hashSizeBytes)]);
    });
    return output;
}

export function decodeWinternitz32_3(input: bigint[], chunkIndex: number): bigint {
    const nibbles: number[] = [];
    const dataNibbles = 11;
    const publicKeys = getWinternitzPublicKeys32_3(chunkIndex);
    for (let i = 0; i < dataNibbles; i++) {
        let h = input[i];
        for (let j = 0; j < 8; j++) {
            h = hash(h);
            if (h == publicKeys[i]) {
                nibbles.push(j);
                break;
            }
        }
        if (h != publicKeys[i]) throw new Error('Decoding error');
    }
    let n = 0n;
    nibbles.forEach((tn, i) => {
        n += BigInt(tn) << (BigInt(i) * 3n);
    });
    return n;
}

export function encodeWinternitz256_3(input: bigint, chunkIndex: number): Buffer {
    const checksumNibbles = 4;
    const dataNibbles = 86;
    const hashSizeBytes = 32;
    let output = Buffer.from([]);
    let checksum = 0;
    const privateKeys = getWinternitzPrivateKeys256_3(chunkIndex);
    toNibbles(input, dataNibbles, 3).forEach((nibble, i) => {
        checksum += nibble;
        const t = 7 - nibble;
        output = Buffer.concat([output, bigintToBufferBE(hash(privateKeys[i], t), hashSizeBytes)]);
    });
    toNibbles(BigInt(checksum), checksumNibbles, 3).forEach((nibble, i) => {
        output = Buffer.concat([output, bigintToBufferBE(hash(privateKeys[86 + i], nibble), hashSizeBytes)]);
    });
    return output;
}

export function decodeWinternitz256_3(input: bigint[], chunkIndex: number): bigint {
    const nibbles: number[] = [];
    const dataNibbles = 86;
    const publicKeys = getWinternitzPublicKeys256_3(chunkIndex);
    for (let i = 0; i < dataNibbles; i++) {
        let h = input[i];
        for (let j = 0; j < 8; j++) {
            h = hash(h);
            if (h == publicKeys[i]) {
                nibbles.push(j);
                break;
            }
        }
        if (h != publicKeys[i]) throw new Error('Decoding error');
    }
    let n = 0n;
    nibbles.forEach((tn, i) => {
        n += BigInt(tn) << (BigInt(i) * 3n);
    });
    return n;
}


