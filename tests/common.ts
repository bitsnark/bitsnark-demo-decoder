import { decodeWinternitz256_3 } from "../src/encoding/winternitz_3";

export enum ProtocolStep {
    INITIAL = 'INITIAL',
    CHALLENGE = 'CHALLENGE',
    STEP1 = 'STEP1',
    TRANSITION = 'TRANSITION',
    STEP2 = 'STEP2',
    FINAL = 'FINAL'
};

const stepToNum = {
    [ProtocolStep.INITIAL]: 0,
    [ProtocolStep.CHALLENGE]: 1,
    [ProtocolStep.STEP1]: 2,
    [ProtocolStep.TRANSITION]: 3,
    [ProtocolStep.STEP2]: 4,
    [ProtocolStep.FINAL]: 5,
};

export enum ProtocolRole {
    PAT = 'PAT',
    VIC = 'VIC'
}

export function getEncodingIndexForPat(step: ProtocolStep, iteration: number, registerIndex: number): number {
    return stepToNum[step] * 1000000 + iteration * 256 * 256 + registerIndex * 256;
}

export function getEncodingIndexForVic(step: ProtocolStep, iteration: number): number {
    return stepToNum[step] * 32 + iteration;
}

export function initialPatDecode(encodedProof: bigint[]): bigint[] {
    const proof: bigint[] = [];
    for (let i = 0; i < encodedProof.length / 90; i++) {
        const chunk = encodedProof.slice(i * 90, i * 90 + 90);
        const chunkIndex = getEncodingIndexForPat(ProtocolStep.INITIAL, 0, i);
        proof[i] = decodeWinternitz256_3(chunk, chunkIndex);
    }
    return proof;
}
