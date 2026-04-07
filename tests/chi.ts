/**
 * QuarkDash Crypto Chi-Square Test
 *
 * @git             https://github.com/devsdaddy/quarkdash
 * @version         1.0.0
 * @author          Elijah Rastorguev
 * @build           1000
 * @website         https://dev.to/devsdaddy
 */
import {CipherType, QuarkDash, QuarkDashUtils} from "../src";

/**
 * Chi Square Test
 * @param data {Uint8Array} Data buffer
 */
function chiSquareTest(data: Uint8Array): { chi2: number, p: number, passed: boolean } {
    const observed = new Array(256).fill(0);
    for (let i = 0; i < data.length; i++) {
        observed[data[i]]++;
    }
    const expected = data.length / 256;
    let chi2 = 0;
    for (let i = 0; i < 256; i++) {
        const diff = observed[i] - expected;
        chi2 += (diff * diff) / expected;
    }

    // p-value
    const threshold95 = 293.2;
    const passed = chi2 <= threshold95 && chi2 >= 198.5;
    console.log(chi2);
    return { chi2, p: 0.5, passed };
}

describe('Chi-square test for cipher keystream', () => {
    test('ChaCha20 keystream chi-square', async () => {
        const alice = new QuarkDash({ cipher: CipherType.ChaCha20 });
        const bob = new QuarkDash({ cipher: CipherType.ChaCha20 });
        const alicePub = await alice.generateKeyPair() as Uint8Array;
        const bobPub = await bob.generateKeyPair() as Uint8Array;
        const ciphertext = await alice.initializeSession(bobPub, true) as Uint8Array;
        await bob.initializeSession(alicePub, false);
        await bob.finalizeSession(ciphertext);

        // Генерируем 1 МБ ключевого потока (шифруем нули)
        const plain = new Uint8Array(1024 * 64);
        const encrypted = await alice.encrypt(plain);
        const { chi2, passed } = chiSquareTest(encrypted);
        console.log(`ChaCha20 χ² = ${chi2.toFixed(2)}`);
        expect(passed).toBe(true);
    });
});