import * as fs from 'fs';
import * as snarkjs from 'snarkjs';
import { initialPatDecode } from '../common';

const vkey_path = './tests/step1/groth16/verification_key.json';

describe("groth16 verify", function () {

    let publicSignals: any = null;
    let proof: any = null;
    let vKey: any;

    beforeAll(async () => {
        vKey = JSON.parse(fs.readFileSync(vkey_path).toString());

        const witnessTxt = fs.readFileSync('./tests/step1/witness.txt');
        const encodedWitness = witnessTxt.toString().split('\n').filter(s => s).map(s => BigInt('0x' + s));
        const decodedWitness = initialPatDecode(encodedWitness);


        proof = {
            "pi_a": [
                decodedWitness[0],
                decodedWitness[1],
                "1"],
            "pi_b": [
                [
                    decodedWitness[3],
                    decodedWitness[2]],
                [
                    decodedWitness[5],
                    decodedWitness[4]],
                ["1", "0"]],
            "pi_c": [
                decodedWitness[6],
                decodedWitness[7],
                "1"],
            "protocol": "groth16",
            "curve": "bn128"
        };
        publicSignals = [decodedWitness[8], decodedWitness[9]];
    });

    describe('snarkjs', () => {
        it("sanity: snarkjs groth16 verify SUCCESS", async () => {
            const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);
            expect(res).toBe(true);
        });
    });
});
